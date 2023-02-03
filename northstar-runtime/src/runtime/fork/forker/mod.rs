use self::channel::Channel;

use super::{
    super::error::Error,
    init,
    util::{self},
};
use crate::{
    common::{container::Container, non_nul_string::NonNulString},
    npk::manifest::Manifest,
    runtime::{
        config::Config,
        ipc::{AsyncFramedUnixStream, FramedUnixStream},
        runtime::Pid,
    },
};
use anyhow::{Context, Result};
use log::debug;
pub use messages::{Message, Notification};
use nix::{
    sys::signal::{signal, SigHandler, Signal},
    unistd,
};
use std::{
    os::unix::{net::UnixStream, prelude::OwnedFd},
    process::exit,
};
use tokio::runtime;

mod channel;
mod messages;
mod process;

pub type Args = Vec<NonNulString>;
pub type Env = Vec<NonNulString>;

pub struct Streams {
    pub command_stream: UnixStream,
    pub socket_stream: UnixStream,
    pub notification_stream: UnixStream,
}

/// Fork the forker process
pub fn start() -> Result<(Pid, Streams)> {
    let (command_first, command_second) = UnixStream::pair()?;
    let (socket_first, socket_second) = UnixStream::pair()?;
    let (notification_first, notification_second) = UnixStream::pair()?;

    let pid = match unsafe { unistd::fork() }? {
        unistd::ForkResult::Parent { child } => child.as_raw() as Pid,
        unistd::ForkResult::Child => {
            util::set_child_subreaper(true);
            util::set_parent_death_signal(Signal::SIGKILL);
            util::set_process_name("northstar-fork");

            drop(command_first);
            drop(socket_first);
            drop(notification_first);

            debug!("Setting signal handlers for SIGINT and SIGHUP");
            unsafe {
                signal(Signal::SIGINT, SigHandler::SigIgn)
                    .context("setting SIGINT handler failed")?;
                signal(Signal::SIGHUP, SigHandler::SigIgn)
                    .context("setting SIGHUP handler failed")?;
            }

            let run = process::run(command_second, socket_second, notification_second);
            runtime::Builder::new_current_thread()
                .thread_name("northstar-fork-runtime")
                .enable_io()
                .build()
                .expect("failed to start runtime")
                .block_on(run);
            exit(0);
        }
    };

    let forker = Streams {
        command_stream: command_first,
        socket_stream: socket_first,
        notification_stream: notification_first,
    };

    Ok((pid, forker))
}

/// Handle to the forker process. This is used in the runtime to interfact
/// with the forker process.
#[derive(Debug)]
pub struct Forker {
    channel: Channel,
}

impl Forker {
    /// Create a new forker handle
    pub fn new(command_stream: UnixStream, socket_stream: UnixStream) -> Self {
        // Important: The AsyncFramedUnixStream *must* be constructed in the context
        // of the Tokio runtime that will poll the stream. This is the reason why
        // this fn takes UnixStream from `std`.
        let command_stream = AsyncFramedUnixStream::new(command_stream);
        let socket_stream = FramedUnixStream::new(socket_stream);
        let channel = Channel::new(command_stream, socket_stream);
        Self { channel }
    }

    /// Send a request to the forker process to create a new container.
    pub async fn create<'a, I: Iterator<Item = &'a Container> + Clone>(
        &mut self,
        container: &Container,
        config: &Config,
        manifest: &Manifest,
        io: [OwnedFd; 3],
        console: Option<OwnedFd>,
        containers: I,
    ) -> Result<Pid, Error> {
        debug_assert_eq!(manifest.console.is_some(), console.is_some());

        // Request
        let init = init::build(config, manifest, containers).await?;
        let request = Message::CreateRequest { init, io, console };
        self.channel.send(request).await;

        // Response
        match self.channel.recv().await {
            Some(Message::CreateResult { result }) => {
                result.map_err(|e| Error::StartContainerFailed(container.clone(), e))
            }
            Some(message) => panic!("unexpected message from forker: {message:?}"),
            None => panic!("forker stream closed"),
        }
    }

    /// Start container process in a previously created container.
    pub async fn exec(
        &mut self,
        container: Container,
        path: NonNulString,
        args: Args,
        env: Env,
    ) -> Result<(), Error> {
        // Request
        let request = Message::ExecRequest {
            container,
            path,
            args,
            env,
        };
        self.channel.send(request).await;

        // Response
        match self.channel.recv().await {
            Some(Message::ExecResult { .. }) => Ok(()),
            Some(message) => panic!("unexpected message from forker: {message:?}"),
            None => panic!("forker stream closed"),
        }
    }
}
