use super::{
    super::{error::Error, Pid},
    init,
    util::{self},
};
use crate::{
    common::{container::Container, non_nul_string::NonNulString},
    npk::manifest::Manifest,
    runtime::{
        config::Config,
        ipc::{AsyncFramedUnixStream, FramedUnixStream},
    },
};
use anyhow::{Context, Result};
use futures::FutureExt;
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

mod messages;
mod process;

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

            let run = async move {
                process::run(command_second, socket_second, notification_second).await;
            };

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
    /// Framed stream/sink for sending messages to the forker process
    command_stream: AsyncFramedUnixStream,
    /// Unix socket stream for file descriptor transfer
    socket_stream: FramedUnixStream,
}

impl Forker {
    /// Create a new forker handle
    pub fn new(command_stream: UnixStream, socket_stream: UnixStream) -> Self {
        let command_stream = AsyncFramedUnixStream::new(command_stream);
        let socket_stream = FramedUnixStream::new(socket_stream);
        Self {
            command_stream,
            socket_stream,
        }
    }

    /// Send a request to the forker process to create a new container
    pub async fn create<'a, I: Iterator<Item = &'a Container> + Clone>(
        &mut self,
        config: &Config,
        manifest: &Manifest,
        io: [OwnedFd; 3],
        console: Option<OwnedFd>,
        containers: I,
    ) -> Result<Pid, Error> {
        debug_assert_eq!(manifest.console.is_some(), console.is_some());

        let init = init::build(config, manifest, containers).await?;
        let io = Some(io);
        let message = Message::CreateRequest { init, io, console };

        match self
            .request_response(message)
            .await
            .context("failed to send request")?
        {
            Message::CreateResult { pid: init } => Ok(init),
            m => panic!("Unexpected forker response {:?}", m),
        }
    }

    /// Start container process in a previously created container
    pub async fn exec(
        &mut self,
        container: Container,
        path: NonNulString,
        args: Vec<NonNulString>,
        env: Vec<NonNulString>,
    ) -> Result<(), Error> {
        let message = Message::ExecRequest {
            container,
            path,
            args,
            env,
        };
        self.request_response(message).await.map(drop)
    }

    /// Send a request to the forker process and wait for a response
    async fn request_response(&mut self, request: Message) -> Result<Message, Error> {
        let mut request = request;

        match request {
            Message::CreateRequest {
                init: _,
                ref mut io,
                ref mut console,
            } => {
                let io = io.take();
                let console = console.take();
                self.command_stream
                    .send(request)
                    .await
                    .context("failed to send request")?;
                self.socket_stream
                    .send_fds(&io.expect("missing io"))
                    .context("failed to send fd")?;
                if let Some(console) = console {
                    self.socket_stream
                        .send_fds(&[console])
                        .context("failed to send fd")?;
                }
            }
            message => {
                self.command_stream
                    .send(message)
                    .await
                    .context("failed to send request")?;
            }
        }

        // Receive reply
        let reply = self
            .command_stream
            .recv()
            .map(|s| s.map(|s| s.expect("invalid message")))
            .await
            .context("failed to receive response from forker")?;

        Ok(reply)
    }
}
