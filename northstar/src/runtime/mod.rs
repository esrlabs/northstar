use crate::{api, api::model::Container};
use config::Config;
use error::Error;
use fmt::Debug;
use futures::{future::ready, FutureExt};
use log::debug;
use nix::{
    libc::{EXIT_FAILURE, EXIT_SUCCESS},
    sys::signal,
};
use repository::Repository;
use state::State;
use std::{
    fmt::{self},
    future::Future,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
};
use sync::mpsc;
use tokio::{
    sync::{self, broadcast, oneshot},
    task,
};
use tokio_util::sync::CancellationToken;

mod cgroups;
/// Runtime configuration
pub mod config;
mod console;
mod debug;
mod error;
mod key;
mod mount;
mod pipe;
pub(crate) mod process;
mod repository;
mod state;
pub(crate) mod stats;

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
const ENV_NAME: &str = "NAME";
/// Environment variable name passed to the container with the containers version
const ENV_VERSION: &str = "VERSION";

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
#[derive(Clone, Debug)]
pub enum ExitStatus {
    /// Process exited with exit code
    Exit(ExitCode),
    /// Process was terminated by a signal
    Signaled(signal::Signal),
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

/// Result of a Runtime action
pub type RuntimeResult = Result<(), Error>;

/// Handle to the Northstar runtime
pub struct Runtime {
    /// Channel receive a stop signal for the runtime
    /// Drop the tx part to gracefully shutdown the mail loop.
    stop: CancellationToken,
    // Channel to signal the runtime exit status to the caller of `start`
    // When the runtime is shut down the result of shutdown is sent to this
    // channel. If a error happens during normal operation the error is also
    // sent to this channel.
    stopped: oneshot::Receiver<RuntimeResult>,
    // Runtime task
    task: task::JoinHandle<()>,
}

impl Runtime {
    /// Start runtime with configuration `config`
    pub async fn start(config: Config) -> Result<Runtime, Error> {
        config.check().await?;

        let stop = CancellationToken::new();
        let (stopped_tx, stopped) = oneshot::channel();

        // Start a task that drives the main loop and wait for shutdown results
        let stop_task = stop.clone();
        let task = task::spawn(async move {
            match runtime_task(&config, stop_task).await {
                Err(e) => {
                    log::error!("Runtime error: {}", e);
                    stopped_tx.send(Err(e)).ok();
                }
                Ok(_) => drop(stopped_tx.send(Ok(()))),
            };
        });

        Ok(Runtime {
            stop,
            stopped,
            task,
        })
    }

    /// Stop the runtime and wait for the termination
    pub fn shutdown(self) -> impl Future<Output = RuntimeResult> {
        self.stop.cancel();
        let stopped = self.stopped;
        self.task.then(|_| {
            stopped.then(|n| match n {
                Ok(n) => ready(n),
                Err(_) => ready(Ok(())),
            })
        })
    }
}

impl Future for Runtime {
    type Output = RuntimeResult;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.stopped).poll(cx) {
            Poll::Ready(r) => match r {
                Ok(r) => Poll::Ready(r),
                // Channel error -> tx side dropped
                Err(_) => Poll::Ready(Ok(())),
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn runtime_task(config: &'_ Config, stop: CancellationToken) -> Result<(), Error> {
    let cgroup = Path::new(&*config.cgroup.as_str());
    cgroups::init(cgroup).await?;

    // Northstar runs in a event loop
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(EVENT_BUFFER_SIZE);
    let (notification_tx, _) = sync::broadcast::channel(NOTIFICATION_BUFFER_SIZE);
    let mut state = State::new(config, event_tx.clone(), notification_tx.clone()).await?;

    // Initialize the console if configured

    let console = if let Some(consoles) = config.console.as_ref() {
        if consoles.is_empty() {
            None
        } else {
            let mut console = console::Console::new(event_tx.clone(), notification_tx);
            for url in consoles {
                console.listen(url).await.map_err(Error::Console)?;
            }
            Some(console)
        }
    } else {
        None
    };

    // Wait for a external shutdown request
    task::spawn(async move {
        stop.cancelled().await;
        event_tx.send(Event::Shutdown).await.ok();
    });

    // Enter main loop
    loop {
        if let Err(e) = match event_rx.recv().await.unwrap() {
            // Process console events enqueued by console::Console
            Event::Console(mut msg, txr) => state.on_request(&mut msg, txr).await,
            // The runtime os commanded to shut down and exit.
            Event::Shutdown => {
                debug!("Shutting down Northstar runtime");
                if let Some(console) = console {
                    debug!("Shutting down console");
                    console.shutdown().await.map_err(Error::Console)?;
                }
                break state.shutdown().await;
            }
            // Container event
            Event::Container(container, event) => state.on_event(&container, &event).await,
        } {
            break Err(e);
        }
    }?;

    cgroups::shutdown(cgroup).await?;

    debug!("Shutdown complete");

    Ok(())
}
