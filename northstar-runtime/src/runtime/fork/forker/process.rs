use super::{
    init,
    init::Init,
    messages::{Message, Notification},
};
use crate::{
    common::{container::Container, non_nul_string::NonNulString},
    runtime::{
        fork::util::set_parent_death_signal,
        ipc::{AsyncFramedUnixStream, FramedUnixStream},
        ExitStatus, Pid,
    },
};
use anyhow::{anyhow, Context, Result};
use futures::{
    stream::{FuturesUnordered, StreamExt},
    Future,
};
use itertools::Itertools;
use log::{debug, warn};
use nix::{
    errno::Errno,
    libc::{STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO},
    sched,
    sys::{signal::Signal, wait::waitpid},
    unistd::{self, fork, ForkResult},
};
use std::{
    collections::HashMap,
    os::unix::{
        net::UnixStream,
        prelude::{AsRawFd, OwnedFd},
    },
    process::exit,
};
use tokio::select;

/// Entry point of the forker process
pub async fn run(
    command_stream: UnixStream,
    socket_stream: UnixStream,
    notifications: UnixStream,
) -> ! {
    let mut inits = HashMap::<Container, (Pid, FramedUnixStream)>::new();
    let mut exits = FuturesUnordered::new();

    // Notifications from the forker to the runtime
    let mut notifications = AsyncFramedUnixStream::new(notifications);
    // Message from the runtime to the forker process
    let mut command_stream = AsyncFramedUnixStream::new(command_stream);
    // Socket sent from the runtime to the forker process
    let mut socket_stream = FramedUnixStream::new(socket_stream);

    debug!("Entering main loop");

    loop {
        select! {
            request = recv_command(&mut command_stream, &mut socket_stream) => {
                match request {
                    Some(Message::CreateRequest { init, console, io }) => {
                        debug!("Creating init process for {}", init.container);
                        let container = init.container.clone();
                        let io = io.expect("create request without io");
                        match create(init, io, console).await {
                            Ok((pid, stream)) => {
                                debug_assert!(!inits.contains_key(&container));
                                inits.insert(container, (pid, stream));
                                command_stream.send(Message::CreateResult { result: Ok(pid) }).await.expect("failed to send response");
                            }
                            Err(e) => {
                                command_stream.send(Message::CreateResult { result: Err(e.to_string())}).await.expect("failed to send response");
                            }
                        }
                    }
                    Some(Message::ExecRequest { container, path, args, env }) => {
                        let (pid, message_stream) = inits.remove(&container).unwrap_or_else(|| panic!("failed to find init process for {}", container));
                        // There's a init - let's exec!
                        let (response, exit) = exec(pid, message_stream, container, path, args, env).await;

                        // Add exit status future of this exec request
                        exits.push(exit);

                        // Send the result of the exec request to the runtime
                        command_stream.send(response).await.expect("failed to send response");
                    }
                    Some(_) => unreachable!("Unexpected message"),
                    None => {
                        debug!("Forker request channel closed. Exiting ");
                        std::process::exit(0);
                    }
                }
            }
            exit = exits.next(), if !exits.is_empty() => {
                let (container, exit_status) = exit.expect("invalid exit status");
                debug!("Forwarding exit status notification of {}: {}", container, exit_status);
                notifications.send(Notification::Exit { container, exit_status }).await.expect("failed to send exit notification");
            }
        }
    }
}

/// Create a new init process ("container")
async fn create(
    init: Init,
    io: [OwnedFd; 3],
    console: Option<OwnedFd>,
) -> Result<(Pid, FramedUnixStream)> {
    let container = init.container.clone();
    debug!("Creating container {}", container);

    let (stream_parent, stream_child) =
        UnixStream::pair().context("failed to create socket pair")?;

    let trampoline_pid = match unsafe { fork().context("failed to fork") }? {
        ForkResult::Parent { child } => child.as_raw() as Pid,
        ForkResult::Child => {
            drop(stream_parent);
            let mut stream = FramedUnixStream::new(stream_child);

            set_parent_death_signal(Signal::SIGKILL);

            // Apply io settings
            let stdin = &io[0];
            let stdout = &io[1];
            let stderr = &io[2];
            unistd::dup2(stdin.as_raw_fd(), STDIN_FILENO).expect("failed to dup2");
            unistd::dup2(stdout.as_raw_fd(), STDOUT_FILENO).expect("failed to dup2");
            unistd::dup2(stderr.as_raw_fd(), STDERR_FILENO).expect("failed to dup2");
            drop(io);

            // Create pid namespace
            sched::unshare(sched::CloneFlags::CLONE_NEWPID)
                .expect("failed to create pid namespace");

            // Fork the init process
            let init_pid = match unsafe { fork().expect("failed to fork") } {
                ForkResult::Parent { child } => child.as_raw() as Pid,
                ForkResult::Child => {
                    // Wait until the forker process received our pid sent
                    // over by the trampoline.
                    drop(stream.recv::<()>());
                    init.run(stream, console)
                }
            };

            // Send the pid of init to the forker process
            stream.send(init_pid).expect("failed to send init pid");
            exit(0);
        }
    };

    // Ensure to close the socket pair end of the child.
    drop(stream_child);

    // Wait for the trampoline to send over the PID of init.
    debug!("Waiting for init pid of container {}", container);
    let mut stream = FramedUnixStream::new(stream_parent);
    let pid = stream.recv()?.ok_or_else(|| anyhow!("stream closed"))?;

    // Notifiy init that we have successfully received their PID and
    // release them into the wild.
    stream.send(()).context("failed to notify init")?;

    // Reap the trampoline process
    debug!("Waiting for trampoline process {} to exit", trampoline_pid);
    let trampoline_pid = unistd::Pid::from_raw(trampoline_pid as i32);
    match waitpid(Some(trampoline_pid), None) {
        Ok(_) | Err(Errno::ECHILD) => (), // Ok - or already reaped
        Err(e) => panic!("failed to wait for the trampoline process: {}", e),
    }

    debug!("Created container {} with pid {}", container, pid);

    Ok((pid, stream))
}

/// Send a exec request to a container
async fn exec(
    init_pid: Pid,
    stream: FramedUnixStream,
    container: Container,
    path: NonNulString,
    args: Vec<NonNulString>,
    env: Vec<NonNulString>,
) -> (Message, impl Future<Output = (Container, ExitStatus)>) {
    let mut stream = stream;

    debug!(
        "Forwarding exec request for container {}: {}",
        container,
        args.iter().map(ToString::to_string).join(" ")
    );

    // Send the exec request to the init process
    // Ignore any error on the stream send because the async block
    // below will take care. If the stream is accidently closed
    // on the other end the process is treated as gone.
    let message = init::Message::Exec { path, args, env };
    drop(stream.send(message));

    let stream = stream.into_inner();
    let mut stream = AsyncFramedUnixStream::new(stream);

    /// Send a SIGKILL to `pid`.
    fn kill(pid: Pid) {
        let process_group = unistd::Pid::from_raw(-(pid as i32));
        warn!("Sending a SIGKILL to {}", process_group);
        nix::sys::signal::kill(process_group, Some(Signal::SIGKILL)).ok();
    }

    // Wait until init tells us that it forked.
    match stream.recv().await.expect("failed to receive") {
        Some(init::Message::Forked { .. }) => (),
        _ => {
            warn!("Unexpected message from init. This shall never happen",);
            kill(init_pid);
        }
    }

    // Construct a future that waits for init to signal a exit of it's child.
    // Afterwards reap the init process which should have exited already.
    let exit_status = async move {
        let exit_status = match stream.recv().await {
            Ok(Some(init::Message::Exit {
                pid: _,
                exit_status,
            })) => exit_status,
            Ok(m) => {
                warn!("Unexpected message from init {:?}", m);
                kill(init_pid);
                ExitStatus::Exit(-1)
            }
            Err(e) => {
                warn!("Unexpected error while waiting for exit status: {}", e);
                kill(init_pid);
                ExitStatus::Exit(-2)
            }
        };

        debug!("Reaping init process of {} ({})", container, init_pid);
        waitpid(unistd::Pid::from_raw(init_pid as i32), None).expect("failed to reap init process");
        (container, exit_status)
    };

    (Message::ExecResult, exit_status)
}

/// Receive a command on the command stream
async fn recv_command(
    stream: &mut AsyncFramedUnixStream,
    socket_stream: &mut FramedUnixStream,
) -> Option<Message> {
    let request = match stream.recv().await {
        Ok(request) => request,
        Err(e) => {
            debug!("Forker request error: {}. Exiting...", e);
            exit(0);
        }
    };

    match request {
        Some(Message::CreateRequest { init, .. }) => {
            let io = socket_stream.recv_fds::<OwnedFd, 3>().ok();
            let console = if init.console {
                let console = socket_stream
                    .recv_fds::<OwnedFd, 1>()
                    .expect("failed to receive console fd");
                Some(console.into_iter().next().expect("missing console fd"))
            } else {
                None
            };
            Some(Message::CreateRequest { init, io, console })
        }
        Some(Message::ExecRequest {
            container,
            path,
            args,
            env,
            ..
        }) => Some(Message::ExecRequest {
            container,
            path,
            args,
            env,
        }),
        command => command,
    }
}
