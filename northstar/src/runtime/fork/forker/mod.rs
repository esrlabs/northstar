use super::{
    super::{error::Error, Pid},
    init,
    util::{self},
};
use crate::{
    common::{container::Container, non_nul_string::NonNulString},
    debug,
    npk::manifest::Manifest,
    runtime::{
        config::Config,
        error::Context,
        fork::util::set_log_target,
        ipc::{owned_fd::OwnedFd, socket_pair, AsyncMessage},
    },
};
use futures::FutureExt;
pub use messages::{Message, Notification};
use nix::sys::signal::{signal, SigHandler, Signal};
use std::os::unix::net::UnixStream as StdUnixStream;
use tokio::{net::UnixStream, runtime};

mod r#impl;
mod messages;

pub struct ForkerChannels {
    pub stream: StdUnixStream,
    pub notifications: StdUnixStream,
}

/// Fork the forker process
pub fn start() -> Result<(Pid, ForkerChannels), Error> {
    let mut stream_pair = socket_pair().expect("failed to open socket pair");
    let mut notifications = socket_pair().expect("failed to open socket pair");

    let pid = util::fork(|| {
        set_log_target("northstar::forker".into());
        util::set_child_subreaper(true);
        util::set_parent_death_signal(Signal::SIGKILL);
        util::set_process_name("northstar-fork");

        let stream = stream_pair.second();
        let notifications = notifications.second();

        debug!("Setting signal handlers for SIGINT and SIGHUP");
        unsafe {
            signal(Signal::SIGINT, SigHandler::SigIgn).context("setting SIGINT handler failed")?;
            signal(Signal::SIGHUP, SigHandler::SigIgn).context("setting SIGHUP handler failed")?;
        }

        debug!("Starting async runtime");
        runtime::Builder::new_current_thread()
            .thread_name("northstar-fork-runtime")
            .enable_time()
            .enable_io()
            .build()
            .expect("failed to start runtime")
            .block_on(async {
                r#impl::run(stream, notifications).await;
            });
        Ok(())
    })
    .expect("failed to start Forker process");

    let forker = ForkerChannels {
        stream: stream_pair.first(),
        notifications: notifications.first(),
    };

    Ok((pid, forker))
}

/// Handle to the forker process
#[derive(Debug)]
pub struct Forker {
    /// Framed stream/sink for sending messages to the forker process
    stream: AsyncMessage<UnixStream>,
}

impl Forker {
    /// Create a new forker handle
    pub fn new(stream: StdUnixStream) -> Self {
        let stream = stream.try_into().expect("failed to create AsyncMessage");
        Self { stream }
    }

    /// Send a request to the forker process to create a new container
    pub async fn create(
        &mut self,
        config: &Config,
        manifest: &Manifest,
        console: Option<OwnedFd>,
        containers: &(impl Iterator<Item = &Container> + Clone),
    ) -> Result<Pid, Error> {
        debug_assert_eq!(manifest.console.is_some(), console.is_some());

        let init = init::build(config, manifest, containers).await?;
        let console = console.map(Into::into);
        let message = Message::CreateRequest { init, console };

        match self
            .request_response(message)
            .await
            .expect("failed to send request")
        {
            Message::CreateResult { init } => Ok(init),
            Message::Failure(error) => {
                Err(Error::StartContainerFailed(manifest.container(), error))
            }
            _ => panic!("Unexpected forker response"),
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

    /// Send a request to the forker process
    async fn request_response(&mut self, request: Message) -> Result<Message, Error> {
        let mut request = request;

        // Remove fds from message
        let fds = match &mut request {
            Message::CreateRequest { init: _, console } => {
                console.take().map(|console| Vec::from([console]))
            }
            Message::ExecRequest { io, .. } => io.take().map(Vec::from),
            _ => None,
        };

        // Send it
        self.stream
            .send(request)
            .await
            .context("failed to send request")?;

        // Send fds if any
        if let Some(fds) = fds {
            self.stream
                .send_fds(&fds)
                .await
                .context("failed to send fd")?;
            drop(fds);
        }

        // Receive reply
        let reply = self
            .stream
            .recv()
            .map(|s| s.map(|s| s.unwrap()))
            .await
            .context("failed to receive response from forker")?;

        Ok(reply)
    }
}
