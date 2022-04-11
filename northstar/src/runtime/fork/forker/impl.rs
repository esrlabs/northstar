use super::{
    init,
    init::Init,
    messages::{Message, Notification},
    util::fork,
};
use crate::{
    common::{container::Container, non_nul_string::NonNulString},
    debug,
    runtime::{
        fork::util::{self, set_log_target},
        ipc::{self, owned_fd::OwnedFd, socket_pair, AsyncMessage, Message as IpcMessage},
        ExitStatus, Pid,
    },
};
use futures::{
    stream::{FuturesUnordered, StreamExt},
    Future,
};
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
use tokio::{net::UnixStream, select, sync::mpsc, task};

type Inits = HashMap<Container, InitProcess>;

/// Handle the communication between the forker and the init process.
struct InitProcess {
    pid: Pid,
    /// Used to send messages to the init process.
    stream: AsyncMessage<UnixStream>,
}

/// Entry point of the forker process
pub async fn run(stream: StdUnixStream, notifications: StdUnixStream) -> ! {
    let mut notifications: AsyncMessage<UnixStream> = notifications
        .try_into()
        .expect("failed to create async message");
    let mut stream: AsyncMessage<UnixStream> =
        stream.try_into().expect("failed to create async message");
    let mut inits = Inits::new();
    let mut exits = FuturesUnordered::new();

    debug!("Entering main loop");

    let (tx, mut rx) = mpsc::channel(1);

    // Separate tasks for notifications and messages

    task::spawn(async move {
        loop {
            select! {
                exit = rx.recv() => {
                    match exit {
                        Some(exit) => exits.push(exit),
                        None => break,
                    }
                }
                exit = exits.next(), if !exits.is_empty() => {
                    let (container, exit_status) = exit.expect("invalid exit status");
                    debug!("Forwarding exit status notification of {}: {}", container, exit_status);
                    notifications.send(Notification::Exit { container, exit_status }).await.expect("failed to send exit notification");
                }
            }
        }
    });

    loop {
        select! {
            request = recv(&mut stream) => {
                match request {
                    Some(Message::CreateRequest { init, console }) => {
                        let container = init.container.clone();

                        if inits.contains_key(&container) {
                            let error = format!("container {} already created", container);
                            log::warn!("{}", error);
                            stream.send(Message::Failure(error)).await.expect("failed to send response");
                            continue;
                        }

                        debug!("Creating init process for {}", init.container);
                        let (pid, init_process) = create(init, console).await;
                        inits.insert(container, init_process);
                        stream.send(Message::CreateResult { init: pid }).await.expect("failed to send response");
                    }
                    Some(Message::ExecRequest { container, path, args, env, io }) => {
                        let io = io.unwrap();
                        if let Some(init) = inits.remove(&container) {
                            let (response, exit) = exec(init, container, path, args, env, io).await;
                            tx.send(exit).await.ok();
                            stream.send(response).await.expect("failed to send response");
                        } else {
                            let error = format!("Container {} not created", container);
                            log::warn!("{}", error);
                            stream.send(Message::Failure(error)).await.expect("failed to send response");
                        }
                    }
                    Some(_) => unreachable!("Unexpected message"),
                    None => {
                        debug!("Forker request channel closed. Exiting ");
                        std::process::exit(0);
                    }
                }
            }
        }
    }
}

/// Create a new init process ("container")
async fn create(init: Init, console: Option<OwnedFd>) -> (Pid, InitProcess) {
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
        .unwrap();

    // Reap the trampoline process
    debug!("Waiting for trampoline process {} to exit", trampoline_pid);
    let trampoline_pid = unistd::Pid::from_raw(trampoline_pid as i32);
    match waitpid(Some(trampoline_pid), None) {
        Ok(_) | Err(Errno::ECHILD) => (), // Ok - or reaped by the reaper thread
        Err(e) => panic!("failed to wait for the trampoline process: {}", e),
    }

    debug!("Created container {} with pid {}", container, pid);

    (pid, InitProcess { pid, stream })
}

/// Send a exec request to a container
async fn exec(
    mut init: InitProcess,
    container: Container,
    path: NonNulString,
    args: Vec<NonNulString>,
    env: Vec<String>,
    io: [OwnedFd; 3],
) -> (Message, impl Future<Output = (Container, ExitStatus)>) {
    debug_assert!(io.len() == 3);

    debug!(
        "Forwarding exec request for container {}: {}",
        container,
        args.iter().map(ToString::to_string).join(" ")
    );

    // Send the exec request to the init process
    let message = init::Message::Exec { path, args, env };
    init.stream
        .send(message)
        .await
        .expect("failed to send exec to init");

    // Send io file descriptors
    init.stream.send_fds(&io).await.expect("failed to send fd");
    drop(io);

    match init.stream.recv().await.expect("failed to receive") {
        Some(init::Message::Forked { .. }) => (),
        _ => panic!("Unexpected init message"),
    }

    // Construct a future that waits to the init to signal a exit of it's child
    // Afterwards reap the init process which should have exited already
    let exit = async move {
        match init.stream.recv().await {
            Ok(Some(init::Message::Exit {
                pid: _,
                exit_status,
            })) => {
                // Reap init process
                debug!("Reaping init process of {} ({})", container, init.pid);
                waitpid(unistd::Pid::from_raw(init.pid as i32), None)
                    .expect("failed to reap init process");
                (container, exit_status)
            }
            Ok(None) | Err(_) => {
                // Reap init process
                debug!("Reaping init process of {} ({})", container, init.pid);
                waitpid(unistd::Pid::from_raw(init.pid as i32), None)
                    .expect("failed to reap init process");
                (container, ExitStatus::Exit(-1))
            }
            Ok(_) => panic!("Unexpected message from init"),
        }
    };

    (Message::ExecResult, exit)
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
                io: Some(io),
            })
        }
        m => m,
    }
}
