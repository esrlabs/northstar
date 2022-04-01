use crate::{api, api::model::Container, runtime::ipc::AsyncMessage};
use async_stream::stream;
use config::Config;
use error::Error;
use fmt::Debug;
use futures::{
    future::{ready, Either},
    FutureExt, StreamExt,
};
use log::{debug, info};
use nix::{
    libc::{EXIT_FAILURE, EXIT_SUCCESS},
    sys::{
        self,
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd,
};
use serde::{Deserialize, Serialize};
use state::State;
use std::{
    convert::TryFrom,
    fmt::{self},
    future::Future,
    path::Path,
};
use sync::mpsc;
use tokio::{
    pin, select,
    sync::{self, broadcast, oneshot},
    task::{self, JoinHandle},
};
use tokio_util::sync::{CancellationToken, DropGuard};

use self::fork::ForkerChannels;

mod cgroups;
mod console;
mod debug;
mod error;
mod fork;
mod io;
mod ipc;
mod key;
mod mount;
mod repository;
mod state;
pub(crate) mod stats;

/// Runtime configuration
pub mod config;

type EventTx = mpsc::Sender<Event>;
type NotificationTx = broadcast::Sender<(Container, ContainerEvent)>;
type RepositoryId = String;
type ExitCode = i32;
type Pid = u32;

/// Buffer size of the main loop channel
const EVENT_BUFFER_SIZE: usize = 1000;
/// Buffer size of the notification channel
const NOTIFICATION_BUFFER_SIZE: usize = 1000;

/// Environment variable name passed to the container with the containers name
const ENV_NAME: &str = "NORTHSTAR_NAME";
/// Environment variable name passed to the container with the containers version
const ENV_VERSION: &str = "NORTHSTAR_VERSION";
/// Environment variable name passed to the container with the containers id
const ENV_CONTAINER: &str = "NORTHSTAR_CONTAINER";
/// Environment variable name passed to the container with the console fd
const ENV_CONSOLE: &str = "NORTHSTAR_CONSOLE";

#[derive(Debug)]
enum Event {
    /// Incoming console command
    Console(console::Request, oneshot::Sender<api::model::Response>),
    /// Northstar shall shut down
    Shutdown,
    /// Container event
    Container(Container, ContainerEvent),
}

#[derive(Clone, Debug)]
enum ContainerEvent {
    /// Container has been started
    Started,
    /// Container exited with status
    Exit(ExitStatus),
    /// Container is installed
    Installed,
    /// Container is uninstalled
    Uninstalled,
    /// CGroup event
    CGroup(CGroupEvent),
}

/// Events generated by cgroup controllers
#[derive(Clone, Debug)]
enum CGroupEvent {
    Memory(MemoryEvent),
}

#[derive(Clone, Default, Debug)]
struct MemoryEvent {
    /// The number of times the cgroup is reclaimed due to
    /// high memory pressure even though its usage is under
    /// the low boundary.  This usually indicates that the low
    /// boundary is over-committed.
    low: Option<u64>,
    /// The number of times processes of the cgroup are
    /// throttled and routed to perform direct memory reclaim
    /// because the high memory boundary was exceeded.  For a
    /// cgroup whose memory usage is capped by the high limit
    /// rather than global memory pressure, this event's
    /// occurrences are expected.
    high: Option<u64>,
    /// The number of times the cgroup's memory usage was
    /// about to go over the max boundary.  If direct reclaim
    /// fails to bring it down, the cgroup goes to OOM state.
    max: Option<u64>,
    /// The number of time the cgroup's memory usage was
    /// reached the limit and allocation was about to fail.
    /// Depending on context result could be invocation of OOM
    /// killer and retrying allocation or failing allocation.
    /// Failed allocation in its turn could be returned into
    /// userspace as -ENOMEM or silently ignored in cases like
    /// disk readahead. For now OOM in memory cgroup kills
    /// tasks if shortage has happened inside page fault.
    oom: Option<u64>,
    /// The number of processes belonging to this cgroup
    /// killed by any kind of OOM killer.
    oom_kill: Option<u64>,
}

/// Container exit status
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ExitStatus {
    /// Process exited with exit code
    Exit(ExitCode),
    /// Process was terminated by a signal
    Signalled(u8),
}

impl From<Signal> for ExitStatus {
    fn from(signal: Signal) -> Self {
        ExitStatus::Signalled(signal as u8)
    }
}

impl From<ExitCode> for ExitStatus {
    fn from(code: ExitCode) -> Self {
        ExitStatus::Exit(code)
    }
}

impl ExitStatus {
    /// Exit success
    pub const SUCCESS: ExitCode = EXIT_SUCCESS;
    /// Exit failure
    pub const FAILURE: ExitCode = EXIT_FAILURE;

    /// Returns true if the exist status is success
    pub fn success(&self) -> bool {
        matches!(self, ExitStatus::Exit(code) if *code == Self::SUCCESS)
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExitStatus::Exit(code) => write!(f, "Exit({})", code),
            ExitStatus::Signalled(signal) => match sys::signal::Signal::try_from(*signal as i32) {
                Ok(signal) => write!(f, "Signalled({})", signal),
                Err(_) => write!(f, "Signalled({})", signal),
            },
        }
    }
}

/// Runtime handle
#[allow(clippy::large_enum_variant)]
pub enum Runtime {
    /// The runtime is created but not yet started.
    Created {
        /// Runtime configuration
        config: Config,
        /// Forker pid
        forker_pid: Pid,
        /// Forker channles
        forker_channels: ForkerChannels,
    },
    /// The runtime is started.
    Running {
        /// Drop guard to stop the runtime
        guard: DropGuard,
        /// Runtime task
        task: JoinHandle<Result<(), Error>>,
    },
}

impl Runtime {
    /// Create new runtime instance
    pub fn new(config: Config) -> Result<Runtime, Error> {
        let (forker_pid, forker_channels) = fork::start()?;
        Ok(Runtime::Created {
            config,
            forker_pid,
            forker_channels,
        })
    }

    /// Start runtime with configuration `config`
    pub async fn start(self) -> Result<Runtime, Error> {
        let (config, forker_pid, forker_channels) = if let Runtime::Created {
            config,
            forker_pid,
            forker_channels,
        } = self
        {
            (config, forker_pid, forker_channels)
        } else {
            panic!("Runtime::start called on a running runtime");
        };

        config.check().await?;

        let token = CancellationToken::new();
        let guard = token.clone().drop_guard();

        // Start a task that drives the main loop and wait for shutdown results
        let task = task::spawn(run(config, token, forker_pid, forker_channels));

        Ok(Runtime::Running { guard, task })
    }

    /// Stop the runtime and wait for the termination
    pub fn shutdown(self) -> impl Future<Output = Result<(), Error>> {
        if let Runtime::Running { guard, task } = self {
            drop(guard);
            Either::Left({
                task.then(|n| match n {
                    Ok(n) => ready(n),
                    Err(_) => ready(Ok(())),
                })
            })
        } else {
            Either::Right(futures::future::ready(Ok(())))
        }
    }

    /// Wait for the runtime to stop
    pub async fn stopped(&mut self) -> Result<(), Error> {
        match self {
            Runtime::Running { ref mut task, .. } => match task.await {
                Ok(r) => r,
                Err(_) => Ok(()),
            },
            Runtime::Created { .. } => panic!("Stopped called on a stopped runtime"),
        }
    }
}

/// Main loop
async fn run(
    config: Config,
    token: CancellationToken,
    forker_pid: Pid,
    forker_channels: ForkerChannels,
) -> Result<(), Error> {
    // Setup root cgroup(s)
    let cgroup = Path::new(config.cgroup.as_str()).to_owned();
    cgroups::init(&cgroup).await?;

    // Join forker
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
                e => panic!("Failed to waitpid on {}: {:?}", pid, e),
            }
        }
    });

    // Northstar runs in a event loop
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(EVENT_BUFFER_SIZE);
    let (notification_tx, _) = sync::broadcast::channel(NOTIFICATION_BUFFER_SIZE);

    // Initialize the console if configured
    let console = if let Some(consoles) = config.console.as_ref() {
        if consoles.is_empty() {
            None
        } else {
            let mut console = console::Console::new(event_tx.clone(), notification_tx.clone());
            for url in consoles {
                console.listen(url).await.map_err(Error::Console)?;
            }
            Some(console)
        }
    } else {
        None
    };

    // Convert stream and stream_fd into Tokio UnixStream
    let (forker, mut exit_notifications) = {
        let ForkerChannels {
            stream,
            notifications,
        } = forker_channels;

        let forker = fork::Forker::new(stream);
        let exit_notifications: AsyncMessage<_> = notifications
            .try_into()
            .expect("Failed to convert exit notification handle");
        (forker, exit_notifications)
    };

    // Merge the exit notification from the forker process with other events into the main loop channel
    let event_rx = stream! {
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
            _ = token.cancelled() => event_tx.send(Event::Shutdown).await.expect("Failed to send shutdown event"),
            // Process events
            event = event_rx.next() => {
                if let Err(e) = match event.unwrap() {
                    // Process console events enqueued by console::Console
                    Event::Console(mut msg, response) => state.on_request(&mut msg, response).await,
                    // The runtime os commanded to shut down and exit.
                    Event::Shutdown => {
                        debug!("Shutting down Northstar runtime");
                        if let Some(console) = console {
                            debug!("Shutting down console");
                            console.shutdown().await.map_err(Error::Console)?;
                        }
                        break state.shutdown(event_rx).await;
                    }
                    // Container event
                    Event::Container(container, event) => state.on_event(&container, &event, false).await,
                } {
                    break Err(e);
                }
            }
            exit_status = &mut join_forker => panic!("Forker exited with {:?}", exit_status),
        }
    }?;

    // Terminate forker process
    debug!("Joining forker with pid {}", forker_pid);
    // signal::kill(forker_pid, Some(SIGTERM)).ok();
    join_forker.await.expect("Failed to join forker");

    // Shutdown cgroups
    cgroups::shutdown(&cgroup).await?;

    debug!("Shutdown complete");

    Ok(())
}
