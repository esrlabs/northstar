use crate::{
    api::model::Container,
    runtime::{
        cgroups,
        config::Config,
        console,
        events::{ContainerEvent, Event},
        exit_status::ExitStatus,
        fork,
        fork::Streams,
        ipc::AsyncFramedUnixStream,
        state::State,
    },
};
use async_stream::stream;
use futures::{
    future::{ready, Either},
    FutureExt, StreamExt,
};
use log::{debug, info};
use nix::{
    sys::wait::{waitpid, WaitStatus},
    unistd,
};
use std::{future::Future, path::Path};
use sync::mpsc;
use thiserror::Error;
use tokio::{
    pin, select,
    sync::{self, broadcast},
    task::{self, JoinHandle},
};
use tokio_util::sync::{CancellationToken, DropGuard};

pub(crate) type NotificationTx = broadcast::Sender<(Container, ContainerEvent)>;
pub(crate) type Pid = u32;

/// Runtime error
#[derive(Error, Debug)]
#[error(transparent)]
pub struct Error(#[from] anyhow::Error);

/// Runtime handle
#[allow(clippy::large_enum_variant)]
pub enum Runtime {
    /// The runtime is created but not yet started.
    Created {
        /// Runtime configuration
        config: Config,
        /// Forker pid and streams
        forker: (Pid, Streams),
    },
    /// The runtime is started.
    Running {
        /// Drop guard to stop the runtime
        guard: DropGuard,
        /// Runtime task
        task: JoinHandle<anyhow::Result<()>>,
    },
}

impl Runtime {
    /// Create new runtime instance
    pub fn new(config: Config) -> Result<Runtime, Error> {
        config.check()?;
        let forker = fork::start()?;
        Ok(Runtime::Created { config, forker })
    }

    /// Start runtime with configuration `config`
    pub async fn start(self) -> Result<Runtime, Error> {
        let (config, forker) = if let Runtime::Created { config, forker } = self {
            (config, forker)
        } else {
            panic!("Runtime::start called on a running runtime");
        };

        let token = CancellationToken::new();
        let guard = token.clone().drop_guard();

        // Start a task that drives the main loop and wait for shutdown results
        let task = task::spawn(run(config, token, forker));

        Ok(Runtime::Running { guard, task })
    }

    /// Stop the runtime and wait for the termination
    pub fn shutdown(self) -> impl Future<Output = Result<(), Error>> {
        if let Runtime::Running { guard, task } = self {
            drop(guard);
            Either::Left({
                task.then(|n| match n {
                    Ok(n) => ready(n.map_err(|e| e.into())),
                    Err(_) => ready(Ok(())),
                })
            })
        } else {
            Either::Right(ready(Ok(())))
        }
    }

    /// Wait for the runtime to stop
    pub async fn stopped(&mut self) -> Result<(), Error> {
        match self {
            Runtime::Running { ref mut task, .. } => match task.await {
                Ok(r) => r.map_err(|e| e.into()),
                Err(_) => Ok(()),
            },
            Runtime::Created { .. } => panic!("Stopped called on a stopped runtime"),
        }
    }
}

/// Main loop
async fn run(
    mut config: Config,
    token: CancellationToken,
    forker: (Pid, Streams),
) -> anyhow::Result<()> {
    // Setup root cgroup(s)
    let cgroup = Path::new(config.cgroup.as_str()).to_owned();
    cgroups::init(&cgroup).await?;

    // Join forker
    let (forker_pid, forker_channels) = forker;
    let mut join_forker = task::spawn_blocking(move || {
        let pid = unistd::Pid::from_raw(forker_pid as i32);
        loop {
            match waitpid(Some(pid), None) {
                Ok(WaitStatus::Exited(_pid, status)) => {
                    break ExitStatus::Exit(status);
                }
                Ok(WaitStatus::Signaled(_pid, status, _)) => {
                    break ExitStatus::Signalled(status as u8);
                }
                Ok(WaitStatus::Continued(_)) | Ok(WaitStatus::Stopped(_, _)) => (),
                Err(nix::Error::EINTR) => (),
                e => panic!("failed to waitpid on {pid}: {e:?}"),
            }
        }
    });

    // Northstar runs in a event loop
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(config.event_buffer_size);
    let (notification_tx, _) = sync::broadcast::channel(config.notification_buffer_size);

    // Initialize the console if bind address configured.
    let console = if let Some(global) = config.console.global.take() {
        let mut console = console::Console::new(event_tx.clone(), notification_tx.clone());
        let options = global.options.unwrap_or_default();
        let permissions = global.permissions;
        console
            .listen(&global.bind, options.into(), permissions.into())
            .await?;
        Some(console)
    } else {
        None
    };

    // Destructure the forker stream handle: Merge the exit notification into the main channel
    // and create a handle to the foker process to be used in the state module;
    let Streams {
        command_stream,
        socket_stream,
        notification_stream,
    } = forker_channels;
    let forker = fork::Forker::new(command_stream, socket_stream);

    // Merge the exit notification from the forker process with other events into the main loop channel
    let event_rx = stream! {
        let mut exit_notifications = AsyncFramedUnixStream::new(notification_stream);
        loop {
            select! {
                Some(event) = event_rx.recv() => yield event,
                Ok(Some(fork::Notification::Exit { container, exit_status })) = exit_notifications.recv() => {
                    let event = ContainerEvent::Exit(exit_status);
                    yield Event::Container(container, event);
                }
                else => unimplemented!(),
            }
        }
    };
    pin!(event_rx);

    let mut state = State::new(config, event_tx.clone(), notification_tx, forker).await?;

    info!("Runtime up and running");

    // Enter main loop
    loop {
        tokio::select! {
            // External shutdown event via the token
            _ = token.cancelled() => event_tx.send(Event::Shutdown).await.expect("failed to send shutdown event"),
            // Process events
            event = event_rx.next() => {
                if let Err(e) = match event.expect("internal error") {
                    // Process console events enqueued by console::Console
                    Event::Console(request, response) => state.on_request(request, response).await,
                    // The runtime os commanded to shut down and exit.
                    Event::Shutdown => {
                        debug!("Shutting down Northstar runtime");
                        if let Some(console) = console {
                            debug!("Shutting down console");
                            console.shutdown().await?;
                        }
                        break state.shutdown(event_rx).await;
                    }
                    // Container event
                    Event::Container(container, event) => state.on_event(&container, &event, false).await,
                } {
                    break Err(e);
                }
            }
            exit_status = &mut join_forker => panic!("Forker exited with {exit_status:?}"),
        }
    }?;

    // Terminate forker process
    debug!("Joining forker with pid {}", forker_pid);
    join_forker.await.expect("failed to join forker");

    info!("Shutting down cgroups");
    cgroups::shutdown(&cgroup)
        .await
        .expect("failed to shutdown cgroups");

    info!("Shutdown complete");

    Ok(())
}
