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
        ipc::{owned_fd::OwnedFd, socket_pair, AsyncFramedUnixStream, FramedUnixStream},
    },
};
use anyhow::{Context, Result};
use futures::FutureExt;
use log::debug;
pub use messages::{Message, Notification};
use nix::sys::signal::{signal, SigHandler, Signal};
use std::os::unix::net::UnixStream;
use tokio::{runtime, task};

mod messages;
mod process;

pub struct Streams {
    pub command_stream: UnixStream,
    pub socket_stream: UnixStream,
    pub notification_stream: UnixStream,
}

/// Fork the forker process
pub fn start() -> Result<(Pid, Streams)> {
    let mut command_stream_pair = socket_pair().expect("failed to open socket pair");
    let mut socket_stream_pair = socket_pair().expect("failed to open socket pair");
    let mut notification_stream_pair = socket_pair().expect("failed to open socket pair");

    let pid = util::fork(|| {
        util::set_child_subreaper(true);
        util::set_parent_death_signal(Signal::SIGKILL);
        util::set_process_name("northstar-fork");

        let command_stream = command_stream_pair.second();
        let socket_stream = socket_stream_pair.second();
        let notification_stream = notification_stream_pair.second();

        debug!("Setting signal handlers for SIGINT and SIGHUP");
        unsafe {
            signal(Signal::SIGINT, SigHandler::SigIgn).context("setting SIGINT handler failed")?;
            signal(Signal::SIGHUP, SigHandler::SigIgn).context("setting SIGHUP handler failed")?;
        }

        let run = async move {
            process::run(command_stream, socket_stream, notification_stream).await;
        };

        runtime::Builder::new_current_thread()
            .thread_name("northstar-fork-runtime")
            .enable_io()
            .build()
            .expect("failed to start runtime")
            .block_on(run);
        Ok(())
    })
    .expect("failed to start forker process");

    let forker = Streams {
        command_stream: command_stream_pair.first(),
        socket_stream: socket_stream_pair.first(),
        notification_stream: notification_stream_pair.first(),
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
        console: Option<OwnedFd>,
        containers: I,
    ) -> Result<Pid, Error> {
        debug_assert_eq!(manifest.console.is_some(), console.is_some());

        let init = init::build(config, manifest, containers).await?;
        let message = Message::CreateRequest { init, console };

        match self
            .request_response(message)
            .await
            .context("failed to send request")?
        {
            Message::CreateResult { pid: init } => Ok(init),
            Message::Error(error) => Err(Error::StartContainerFailed(manifest.container(), error)),
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
        io: [OwnedFd; 3],
    ) -> Result<(), Error> {
        let message = Message::ExecRequest {
            container,
            path,
            args,
            env,
            io: Some(io),
        };
        self.request_response(message).await.map(drop)
    }

    /// Send a request to the forker process and wait for a response
    async fn request_response(&mut self, request: Message) -> Result<Message, Error> {
        let mut request = request;

        // Remove fds from message
        let fds = match &mut request {
            Message::CreateRequest { init: _, console } => {
                console.take().map(|console| vec![console])
            }
            Message::ExecRequest { io, .. } => io.take().map(Vec::from),
            _ => None,
        };

        // Send it
        self.command_stream
            .send(request)
            .await
            .context("failed to send request")?;

        // Send fds if any
        if let Some(fds) = fds {
            task::block_in_place(|| {
                self.socket_stream
                    .send_fds(&fds)
                    .context("failed to send fd")
            })?;
            drop(fds);
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
