use super::{init, init::Init, messages::Message, util::fork};
use crate::{
    common::{container::Container, non_nul_string::NonNulString},
    debug,
    runtime::{
        fork::{
            util::{self, set_log_target},
            Notification,
        },
        ipc::{self, owned_fd::OwnedFd, socket_pair, AsyncMessage, Message as IpcMessage},
        ExitStatus, Pid,
    },
};
use futures::{stream::FuturesUnordered, Future, FutureExt, StreamExt};
use itertools::Itertools;
use nix::{
    errno::Errno,
    sys::{signal::Signal, wait::waitpid},
    unistd,
};
use std::{
    collections::HashMap,
    os::unix::{
        io::FromRawFd,
        net::UnixStream as StdUnixStream,
        prelude::{IntoRawFd, RawFd},
    },
};
use tokio::{
    net::UnixStream,
    select,
    sync::{mpsc, oneshot},
};

type Inits = HashMap<Container, InitProcess>;

type ExitStatusFuture = oneshot::Receiver<ExitStatus>;

#[derive(Debug)]
struct Command {
    path: NonNulString,
    args: Vec<NonNulString>,
    env: Vec<NonNulString>,
    setsid: bool,
    io: [OwnedFd; 3],
}

/// Handle the communication between the forker and the init process.
struct InitProcess {
    /// Init process PID.
    pid: Pid,
    /// Receives futures for exit status of running processes
    exit_rx: mpsc::Receiver<(Pid, ExitStatusFuture)>,
    /// Send exec requests
    exec_tx: mpsc::Sender<Command>,
}

impl InitProcess {
    fn new(
        init_pid: Pid,
        mut stream: AsyncMessage<UnixStream>,
    ) -> (Self, impl Future<Output = ExitStatus>) {
        // Returns the exit status of the processes inside the container.
        let (exit_tx, exit_rx) = mpsc::channel(1);
        // Send the requests to Init to start new processes.
        let (exec_tx, mut exec_rx) = mpsc::channel(1);

        // Exit status of the init process.
        let (init_exit_tx, init_exit_rx) = oneshot::channel();

        // Spawns task that owns the stream used to communicate with the init process. InitProcess
        // communicates with this task throug the two channels.
        //
        //  ┌─────────────┐   exec   ┌────────────┐
        //  │             │─────────►│            │    socket    ┌──────┐
        //  │ InitProcess │          │ async task │◄────────────►│ Init │
        //  │             │◄─────────│            │              └──────┘
        //  └─────────────┘   exit   └────────────┘
        //
        tokio::spawn(async move {
            // Used to track processes inside the contaner that are spawned from the init and
            // forward thir exit status when they exit.
            let mut ps = HashMap::new();

            loop {
                select! {
                    // Incoming messages from the container's init process
                    msg = stream.recv() => {
                        match msg {
                            Ok(Some(init::Message::Forked { pid })) => {
                                let (tx, rx) = oneshot::channel();
                                let entry = ps.insert(pid, tx);
                                debug_assert!(entry.is_none(), "PID already registered");

                                exit_tx
                                    .send((pid, rx))
                                    .await
                                    .expect("failed to send exit status future");
                            }
                            Ok(Some(init::Message::Exit { pid, exit_status })) => {
                                // Note it is possible to receive exit statuses from processes that
                                // are not tracked for being childs of childs. We simply ignore
                                // those and only care for those directly bellow the init.
                                // TODO This does not solve the problem with orphans
                                let tx = match ps.remove(&pid) {
                                    Some(tx) => tx,
                                    None => continue,
                                };

                                // TODO the process exit status is sent as the init exit status
                                // because that's what the runtime and tests expect currently.
                                let init_exit_status = exit_status.clone();

                                tx.send(exit_status)
                                    .expect("failed to send process exit status");

                                // check if last process exited
                                if ps.is_empty() {
                                    // TODO This call is blocking but it should not take long since
                                    // the init process exits as soon as its last child terminates.
                                    let result = waitpid(unistd::Pid::from_raw(init_pid as i32), None).expect("failed to wait for init");
                                    debug!("Init {} exit status: {:?}", init_pid, result);

                                    init_exit_tx.send(init_exit_status).expect("failed to send init exit status");
                                    break;
                                }
                            }
                            Ok(Some(_)) => panic!("unexpected init message"),
                            Ok(None) | Err(_) => {
                                debug!("Init connection closed, exiting");
                                break;
                            }
                        }
                    }
                    // Forward exec requests to the container's init process
                    exec = exec_rx.recv() => {
                        let Command { path, args, env, setsid, io } = exec.expect("failed to receive command");
                        stream
                            .send(init::Message::Exec { path, args, env, setsid })
                            .await
                            .expect("failed to send");

                        stream.send_fds(&io).await.expect("failed to send pty fd");
                    }
                }
            }
        });

        (
            Self {
                pid: init_pid,
                exit_rx,
                exec_tx,
            },
            init_exit_rx.map(|exit| exit.unwrap_or(ExitStatus::Exit(-1))),
        )
    }

    /// Returns the init process PID
    fn pid(&self) -> Pid {
        self.pid
    }

    /// Start a process in the container
    async fn exec(
        &mut self,
        path: NonNulString,
        args: Vec<NonNulString>,
        env: Vec<NonNulString>,
        setsid: bool,
        io: [OwnedFd; 3],
    ) -> (Pid, impl Future<Output = ExitStatus>) {
        self.exec_tx
            .send(Command {
                path,
                args,
                env,
                setsid,
                io,
            })
            .await
            .expect("failed to send command");

        let (pid, exit) = self
            .exit_rx
            .recv()
            .await
            .expect("failed to receive PID and exit status future");

        (pid, exit.map(|s| s.unwrap_or(ExitStatus::Exit(-1))))
    }
}

/// Entry point of the forker process
pub async fn run(stream: StdUnixStream, notifications: StdUnixStream) -> ! {
    let mut notifications: AsyncMessage<UnixStream> = notifications
        .try_into()
        .expect("failed to create async message");
    let mut stream: AsyncMessage<UnixStream> =
        stream.try_into().expect("failed to create async message");
    let mut exits = FuturesUnordered::new();
    let mut ps_exit = FuturesUnordered::new();

    // Bookkeeping of container init processes
    let mut inits = Inits::new();

    debug!("Entering main loop");

    loop {
        select! {
            process_exit = ps_exit.next(), if !ps_exit.is_empty() => {
                let (container, pid, exit_status) = process_exit.expect("invalid exit status");
                debug!("Container {}, process {} exit with status {}", container, pid, exit_status);
            }
            request = recv(&mut stream) => {
                match request {
                    Some(Message::CreateRequest { init, console }) => {
                        debug!("Creating init process for {}", init.container);
                        let container = init.container.clone();

                        if inits.contains_key(&container) {
                            let error = format!("Container {} already created", container);
                            log::warn!("{}", error);
                            stream.send(Message::Failure(error)).await.expect("failed to send response");
                            continue;
                        }

                        debug!("Creating init process for {}", container);
                        let (init_process, exit_fut) = create(init, console).await;
                        let init_pid = init_process.pid();

                        let entry = inits.insert(container.clone(), init_process);
                        debug_assert!(entry.is_none(), "Container already created");

                        exits.push(exit_fut.map(|status| (container, status)));

                        stream.send(Message::CreateResult { init: init_pid }).await.expect("failed to send response");
                    }
                    Some(Message::ExecRequest { container, path, args, env, setsid, io }) => {
                        let io = io.expect("failed to receive io");

                        debug_assert!(io.len() == 3);
                        let init = match inits.get_mut(&container) {
                            Some(init) => init,
                            None => {
                                let error_msg = format!("Container {} has no running init", container);
                                log::warn!("{}", error_msg);
                                stream.send(Message::Failure(error_msg)).await.expect("failed to send response");
                                continue;
                            }
                        };

                        debug!(
                            "Forwarding exec request for container {}: {} {}",
                            container,
                            path,
                            args.iter().map(ToString::to_string).join(" ")
                        );

                        // Send the exec request to the init process
                        let (pid, exit) = init.exec(path, args, env, setsid, io).await;

                        ps_exit.push(exit.map(move |status| (container, pid, status)));

                        stream.send(Message::ExecResult).await.expect("failed to send response");
                    }
                    Some(_) => unreachable!("unexpected message"),
                    None => {
                        debug!("Forker request channel closed. Exiting ");
                        std::process::exit(0);
                    }
                }
            }
            exit = exits.next(), if !exits.is_empty() => {
                let (container, exit_status) = exit.expect("invalid exit status");
                inits.remove(&container);
                debug!("Forwarding exit status notification of {}: {}", container, exit_status);
                notifications.send(Notification::Exit { container, exit_status }).await.expect("failed to send exit notification");
            }
        }
    }
}

/// Create a new init process ("container")
async fn create(
    init: Init,
    console: Option<OwnedFd>,
) -> (InitProcess, impl Future<Output = ExitStatus>) {
    let container = init.container.clone();
    debug!("Creating container {}", container);
    let mut stream = socket_pair().expect("failed to create socket pair");

    let trampoline_pid = fork(|| {
        set_log_target("northstar::forker-trampoline".into());
        util::set_parent_death_signal(Signal::SIGKILL);

        // Create pid namespace
        debug!("Creating pid namespace");
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWPID)
            .expect("failed to create pid namespace");

        // Work around the borrow checker and fork
        let stream = stream.second().into_raw_fd();

        // Fork the init process
        debug!("Forking init of {}", container);
        let init_pid = fork(|| {
            let stream = unsafe { StdUnixStream::from_raw_fd(stream) };
            // Dive into init and never return
            let stream = IpcMessage::from(stream);
            init.run(stream, console);
        })
        .expect("failed to fork init");

        let stream = unsafe { StdUnixStream::from_raw_fd(stream) };

        // Send the pid of init to the forker process
        let mut stream = ipc::Message::from(stream);
        stream.send(init_pid).expect("failed to send init pid");

        debug!("Exiting trampoline");
        Ok(())
    })
    .expect("failed to fork trampoline process");

    let mut stream: AsyncMessage<UnixStream> = stream
        .first_async()
        .map(Into::into)
        .expect("failed to turn socket into async UnixStream");

    debug!("Waiting for init pid of container {}", container);
    let pid = stream
        .recv()
        .await
        .expect("failed to receive init pid")
        .expect("failed to receive init pid");

    // Reap the trampoline process
    debug!("Waiting for trampoline process {} to exit", trampoline_pid);
    let trampoline_pid = unistd::Pid::from_raw(trampoline_pid as i32);
    match waitpid(Some(trampoline_pid), None) {
        Ok(_) | Err(Errno::ECHILD) => (), // Ok - or reaped by the reaper thread
        Err(e) => panic!("failed to wait for the trampoline process: {}", e),
    }

    debug!("Created container {} with pid {}", container, pid);

    InitProcess::new(pid, stream)
}

async fn recv(stream: &mut AsyncMessage<UnixStream>) -> Option<Message> {
    let request = match stream.recv().await {
        Ok(request) => request,
        Err(e) => {
            debug!("Forker request error: {}. Breaking", e);
            std::process::exit(0);
        }
    };
    match request {
        Some(Message::CreateRequest { init, console: _ }) => {
            let console = if init.console {
                debug!("Console is enabled. Waiting for console stream");
                let console = stream
                    .recv_fds::<RawFd, 1>()
                    .await
                    .expect("failed to receive console fd");
                let console = unsafe { OwnedFd::from_raw_fd(console[0]) };
                Some(console)
            } else {
                None
            };
            Some(Message::CreateRequest { init, console })
        }
        Some(Message::ExecRequest {
            container,
            path,
            args,
            env,
            setsid,
            ..
        }) => {
            let io = stream
                .recv_fds::<OwnedFd, 3>()
                .await
                .expect("failed to receive io");
            Some(Message::ExecRequest {
                container,
                path,
                args,
                env,
                setsid,
                io: Some(io),
            })
        }
        m => m,
    }
}
