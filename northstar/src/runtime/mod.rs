// Copyright (c) 2019 - 2020 ESRLabs
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

use crate::api;
use config::Config;
use derive_new::new;
use error::Error;
use log::debug;

use async_trait::async_trait;
use nix::{
    sys::{signal, stat},
    unistd,
};
use proc_mounts::MountIter;
use state::State;
use std::{
    fmt::Display,
    future::Future,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
};
use sync::mpsc;
use tokio::{
    fs, io,
    sync::{self, oneshot},
    task, time,
};
use tokio_util::sync::CancellationToken;

mod cgroups;
pub mod config;
mod console;
#[allow(unused)]
mod device_mapper;
mod error;
mod key;
mod loopdev;
mod minijail;
mod mount;
mod pipe;
mod process_debug;
mod repository;
mod state;

type EventTx = mpsc::Sender<Event>;
type RepositoryId = String;
pub use api::container::*;
use repository::Repository;
use state::MountedContainer;
type ExitCode = i32;
type Pid = u32;

#[async_trait]
trait Process {
    fn pid(&self) -> Pid;
    async fn start(&mut self) -> Result<(), Error>;
    async fn stop(mut self, timeout: time::Duration) -> Result<ExitStatus, Error>;
}

#[async_trait]
trait Launcher {
    type Process: Process + Send + 'static;

    async fn start(event_tx: EventTx, config: Config) -> Result<Self, Error>
    where
        Self: Sized;
    async fn shutdown(&mut self) -> Result<(), Error>
    where
        Self: Sized;

    async fn create(
        &self,
        container: &MountedContainer<Self::Process>,
    ) -> Result<Self::Process, Error>;
}

#[derive(Clone, Debug)]
pub(crate) enum ExitStatus {
    /// Process exited with exit code
    Exit(ExitCode),
    /// Process was terminated by a signal
    Signaled(signal::Signal),
}

impl Display for ExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(new, Clone, Debug)]
pub(crate) enum Notification {
    OutOfMemory(Container),
    Exit {
        container: Container,
        status: ExitStatus,
    },
    Started(Container),
    Stopped(Container),
}

#[derive(Debug)]
enum Event {
    /// Incomming command
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
}

impl Runtime {
    pub async fn start(config: Config) -> Result<Runtime, Error> {
        let stop = CancellationToken::new();
        let (stopped_tx, stopped_rx) = oneshot::channel();

        mkdir_p_rw(&config.run_dir).await?;

        // To avoid setting the mount propagation on the parent mount, we bind
        // mount config.run_dir to config.run_dir and specify the mount
        // propagation there. The reason why the mount propagation is set to
        // MS_PRIVATE is to make the kernel umount everything mounted in this
        // mount namespace when the past process in this namespace exits.
        if !is_self_bind_mounted(&config.run_dir).await? {
            debug!("Bind mounting run dir");
            // Turn the run directory into a mount point
            task::block_in_place(|| {
                nix::mount::mount(
                    Some(&config.run_dir),
                    config.run_dir.as_os_str(),
                    Option::<&str>::None,
                    nix::mount::MsFlags::MS_BIND,
                    Option::<&'static [u8]>::None,
                )
                .map_err(|e| Error::Mount(mount::Error::Os(e)))
            })?;
        }

        // Mark set the mount propagation on run_dir to MS_PRIVATE
        task::block_in_place(|| {
            debug!(
                "Setting mount propagation to MS_PRIVATE on {}",
                config.run_dir.display()
            );
            nix::mount::mount(
                Some(&config.run_dir),
                config.run_dir.as_os_str(),
                Option::<&str>::None,
                nix::mount::MsFlags::MS_PRIVATE | nix::mount::MsFlags::MS_REC,
                Option::<&'static [u8]>::None,
            )
            .map_err(|e| Error::Mount(mount::Error::Os(e)))
        })?;

        mkdir_p_rw(&config.data_dir).await?;
        mkdir_p_rw(&config.log_dir).await?;

        // Start a task that drives the main loop and wait for shutdown results
        {
            let stop = stop.clone();
            task::spawn(async move {
                match runtime_task(&config, stop).await {
                    Err(e) => {
                        log::error!("Runtime error: {}", e);
                        stopped_tx.send(Err(e)).ok();
                    }
                    Ok(_) => drop(stopped_tx.send(Ok(()))),
                };
            });
        }

        Ok(Runtime {
            stop,
            stopped: stopped_rx,
        })
    }

    /// Stop the runtime and wait for the termination
    pub fn shutdown(self) -> impl Future<Output = RuntimeResult> {
        self.stop.cancel();
        self
    }
}

/// Try to determine if a mount point exists that points to the given path
/// TODO: It's not needed that the mount in run dir is a bind mount to itself. In
/// theory any mount can be used.
async fn is_self_bind_mounted(run_dir: &Path) -> Result<bool, Error> {
    let mounts =
        task::block_in_place(MountIter::new).map_err(|e| Error::Io("Mount iter".into(), e))?;
    let run_dir = fs::canonicalize(&run_dir)
        .await
        .map_err(|e| Error::Io("Canonicalize path".into(), e))?;
    task::block_in_place(|| {
        for mount in mounts {
            let mount = mount.map_err(|e| Error::Io("Mount iter".into(), e))?;
            if mount.dest == run_dir {
                return Ok(true);
            }
        }
        Ok(false)
    })
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
    // Northstar runs in a event loop
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(100);

    let mut state = State::<minijail::Minijail>::new(config, event_tx.clone()).await?;

    // Inititalize the console if configured
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
            Event::Console(msg, txr) => state.console_request(&msg, txr).await,
            // The OOM event is signaled by the cgroup memory monitor if configured in a manifest.
            // If a out of memory condition occours this is signaled with `Event::Oom` which
            // carries the id of the container that is oom.
            Event::Oom(container) => state.on_oom(&container).await,
            // A container process existed. Check `process::wait_exit` for details.
            Event::Exit(container, exit_status) => state.on_exit(&container, &exit_status).await,
            // The runtime os commanded to shut down and exit.
            Event::Shutdown => {
                log::debug!("Shutting down Northstar runtime");
                log::debug!("Dropping queued events");
                drop(event_rx);
                if let Some(console) = console {
                    log::debug!("Shutting down console");
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

    task::block_in_place(|| nix::mount::umount(&config.run_dir))
        .map_err(|e| Error::Mount(mount::Error::Os(e)))?;

    Ok(())
}

/// Create path if it does not exist. Ensure that it is
/// read and writeable
async fn mkdir_p_rw(path: &Path) -> Result<(), Error> {
    if path.exists() && !is_rw(&path) {
        let context = format!("Directory {} is not read and writeable", path.display());
        Err(Error::Io(
            context.clone(),
            io::Error::new(io::ErrorKind::PermissionDenied, context),
        ))
    } else {
        debug!("Creating {}", path.display());
        fs::create_dir_all(&path).await.map_err(|error| {
            Error::Io(
                format!("Failed to create directory {}", path.display()),
                error,
            )
        })
    }
}

/// Return true if path is read and writeable
fn is_rw(path: &Path) -> bool {
    match stat::stat(path.as_os_str()) {
        Ok(stat) => {
            let same_uid = stat.st_uid == unistd::getuid().as_raw();
            let same_gid = stat.st_gid == unistd::getgid().as_raw();
            let mode = stat::Mode::from_bits_truncate(stat.st_mode);

            let is_readable = (same_uid && mode.contains(stat::Mode::S_IRUSR))
                || (same_gid && mode.contains(stat::Mode::S_IRGRP))
                || mode.contains(stat::Mode::S_IROTH);
            let is_writable = (same_uid && mode.contains(stat::Mode::S_IWUSR))
                || (same_gid && mode.contains(stat::Mode::S_IWGRP))
                || mode.contains(stat::Mode::S_IWOTH);

            is_readable && is_writable
        }
        Err(_) => false,
    }
}
