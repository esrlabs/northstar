use super::{
    init,
    init::Init,
    messages::{Message, Notification},
    util::fork,
};
use crate::{
    common::{container::Container, non_nul_string::NonNulString},
    runtime::{
        fork::util::{self},
        ipc::{owned_fd::OwnedFd, socket_pair, AsyncFramedUnixStream, FramedUnixStream},
        ExitStatus, Pid,
    },
};
use futures::{
    stream::{FuturesUnordered, StreamExt},
    Future,
};
use itertools::Itertools;
use log::debug;
use nix::{
    errno::Errno,
    sys::{signal::Signal, wait::waitpid},
    unistd,
};
use std::{
    collections::HashMap,
    os::unix::{
        io::FromRawFd,
        net::UnixStream,
        prelude::{IntoRawFd, RawFd},
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
                    Some(Message::CreateRequest { init, console }) => {
                        debug!("Creating init process for {}", init.container);
                        let container = init.container.clone();
                        let (pid, message_stream) = create(init, console).await;
                        debug_assert!(!inits.contains_key(&container));
                        inits.insert(container, (pid, message_stream));
                        command_stream.send(Message::CreateResult { pid }).await.expect("failed to send response");
                    }
                    Some(Message::ExecRequest { container, path, args, env, io }) => {
                        let io = io.expect("exec request without io");
                        let (pid, message_stream) = inits.remove(&container).unwrap_or_else(|| panic!("failed to find init process for {}", container));
                        // There's a init - let's exec!
                        let (response, exit) = exec(pid, message_stream, container, path, args, env, io).await;

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
async fn create(init: Init, console: Option<OwnedFd>) -> (Pid, FramedUnixStream) {
    let container = init.container.clone();
    debug!("Creating container {}", container);
    let mut stream = socket_pair().expect("failed to create socket pair");

    let trampoline_pid = fork(|| {
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
            let stream = FramedUnixStream::new(unsafe { UnixStream::from_raw_fd(stream) });
            // Dive into init and never return
            init.run(stream, console);
        })
        .expect("failed to fork init");

        // Send the pid of init to the forker process
        let stream = unsafe { UnixStream::from_raw_fd(stream) };
        let mut stream = FramedUnixStream::new(stream);
        stream.send(init_pid).expect("failed to send init pid");

        debug!("Exiting trampoline");
        Ok(())
    })
    .expect("failed to fork trampoline process");

    let mut stream = FramedUnixStream::new(stream.first());

    debug!("Waiting for init pid of container {}", container);
    let pid = stream
        .recv()
        .expect("failed to receive init pid")
        .expect("failed to receive init pid");

    // Reap the trampoline process
    debug!("Waiting for trampoline process {} to exit", trampoline_pid);
    let trampoline_pid = unistd::Pid::from_raw(trampoline_pid as i32);
    match waitpid(Some(trampoline_pid), None) {
        Ok(_) | Err(Errno::ECHILD) => (), // Ok - or already reaped
        Err(e) => panic!("failed to wait for the trampoline process: {}", e),
    }

    debug!("Created container {} with pid {}", container, pid);

    (pid, stream)
}

/// Send a exec request to a container
async fn exec(
    init_pid: Pid,
    message_stream: FramedUnixStream,
    container: Container,
    path: NonNulString,
    args: Vec<NonNulString>,
    env: Vec<NonNulString>,
    io: [OwnedFd; 3],
) -> (Message, impl Future<Output = (Container, ExitStatus)>) {
    let mut message_stream = message_stream;

    debug!(
        "Forwarding exec request for container {}: {}",
        container,
        args.iter().map(ToString::to_string).join(" ")
    );

    // Send the exec request to the init process
    let message = init::Message::Exec { path, args, env };
    message_stream
        .send(message)
        .expect("failed to send exec to init");

    // Send io file descriptors
    message_stream.send_fds(&io).expect("failed to send fd");
    drop(io);

    let message_stream = message_stream.into_inner();
    let mut message_stream = AsyncFramedUnixStream::new(message_stream);

    match message_stream.recv().await.expect("failed to receive") {
        Some(init::Message::Forked { .. }) => (),
        _ => panic!("Unexpected message from init"),
    }

    // Construct a future that waits to the init to signal a exit of it's child
    // Afterwards reap the init process which should have exited already
    let exit = async move {
        let exit_status = match message_stream.recv().await {
            Ok(Some(init::Message::Exit {
                pid: _,
                exit_status,
            })) => exit_status,
            Ok(None) | Err(_) => ExitStatus::Exit(-1),
            Ok(_) => panic!("Unexpected message from init"),
        };

        debug!("Reaping init process of {} ({})", container, init_pid);
        waitpid(unistd::Pid::from_raw(init_pid as i32), None).expect("failed to reap init process");
        (container, exit_status)
    };

    (Message::ExecResult, exit)
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
            let console = if init.console {
                let console = socket_stream
                    .recv_fds::<RawFd, 1>()
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
            let io = socket_stream
                .recv_fds::<OwnedFd, 3>()
                .expect("failed to receive io");
            Some(Message::ExecRequest {
                container,
                path,
                args,
                env,
                io: Some(io),
            })
        }
        command => command,
    }
}
