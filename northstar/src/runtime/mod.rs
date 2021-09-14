// Copyright (c) 2019 - 2021 ESRLabs
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

use crate::{api, api::model::Container};
use config::Config;
use derive_new::new;
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
    pin::Pin,
    task::{Context, Poll},
};
use sync::mpsc;
use tokio::{
    sync::{self, oneshot},
    task,
};
use tokio_util::sync::CancellationToken;

mod cgroups;
pub mod config;
mod console;
mod debug;
mod error;
pub mod island;
mod key;
mod mount;
mod pipe;
mod repository;
mod state;

type EventTx = mpsc::Sender<Event>;
type RepositoryId = String;
type ExitCode = i32;
type Pid = u32;

/// Buffer size of the main loop channel
const MAIN_BUFFER: usize = 1000;

/// Environment variable name passed to the container with the containers name
const ENV_NAME: &str = "NAME";
/// Environment variable name passed to the container with the containers version
const ENV_VERSION: &str = "VERSION";

#[derive(Debug)]
enum Event {
    /// Incomming console command
    Console(console::Request, oneshot::Sender<api::model::Response>),
    /// A instance exited with return code
    Exit(Container, ExitStatus),
    /// Out of memory event occured
    Oom(Container),
    /// Northstar shall shut down
    Shutdown,
    /// Notification events
    Notification(Notification),
}

#[derive(Clone, Debug)]
pub enum ExitStatus {
    /// Process exited with exit code
    Exit(ExitCode),
    /// Process was terminated by a signal
    Signaled(signal::Signal),
}

impl ExitStatus {
    pub const SUCCESS: ExitCode = EXIT_SUCCESS;
    pub const FAILURE: ExitCode = EXIT_FAILURE;

    /// Returns true if the exist status is sueccess
    pub fn success(&self) -> bool {
        matches!(self, ExitStatus::Exit(code) if *code == Self::SUCCESS)
    }
}

#[derive(new, Clone, Debug)]
enum Notification {
    OutOfMemory(Container),
    Exit(Container, ExitStatus),
    Install(Container),
    Uninstall(Container),
    Started(Container),
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
    cgroups::init(&config.cgroups).await?;

    // Northstar runs in a event loop
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(MAIN_BUFFER);
    let mut state = State::new(config, event_tx.clone()).await?;

    // Initialize the console if configured
    let console = if let Some(url) = config.console.as_ref() {
        let mut console = console::Console::new(url, event_tx.clone());
        console.listen().await.map_err(Error::Console)?;

        Some(console)
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
            // Debug console commands are handled via the main loop in order to get access
            // to the global state. Therefore the console server receives a tx handle to the
            // main loop and issues `Event::Console`. Processing of the command takes place
            // in the console module but with access to `state`.
            Event::Console(mut msg, txr) => state.console_request(&mut msg, txr).await,
            // The OOM event is signaled by the cgroup memory monitor if configured in a manifest.
            // If a out of memory condition occurs this is signaled with `Event::Oom` which
            // carries the id of the container that is oom.
            Event::Oom(container) => state.on_oom(&container).await,
            // A container process existed. Check `process::wait_exit` for details.
            Event::Exit(container, exit_status) => state.on_exit(container, exit_status).await,
            // The runtime os commanded to shut down and exit.
            Event::Shutdown => {
                debug!("Shutting down Northstar runtime");
                if let Some(console) = console {
                    debug!("Shutting down console");
                    console.shutdown().await.map_err(Error::Console)?;
                }
                break state.shutdown().await;
            }
            // Forward notifications to console
            Event::Notification(notification) => {
                if let Some(console) = console.as_ref() {
                    console.notification(notification).await;
                }
                Ok(())
            }
        } {
            break Err(e);
        }
    }?;

    cgroups::shutdown(&config.cgroups).await?;

    debug!("Shutdown complete");

    Ok(())
}
