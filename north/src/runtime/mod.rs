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

mod cgroups;
pub mod config;
mod console;
#[allow(unused)]
mod device_mapper;
mod error;
mod keys;
mod loopdev;
mod minijail;
mod mount;
mod process;
mod state;

use crate::{api, api::Notification};
use config::Config;
use console::Request;
use error::Error;
use log::{debug, info, Level};
use nix::{
    sys::stat,
    unistd::{self, pipe},
};
use npk::manifest::Name;
use process::ExitStatus;
use state::State;
use std::{
    future::Future,
    io,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
};
use sync::mpsc;
use tokio::{
    fs,
    sync::{self, oneshot},
    task,
};

pub(crate) type EventTx = mpsc::Sender<Event>;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum Event {
    /// Incomming command
    Console(Request, oneshot::Sender<api::Message>),
    /// A instance exited with return code
    Exit(Name, ExitStatus),
    /// Out of memory event occured
    Oom(Name),
    /// North shall shut down
    Shutdown,
    /// Stdout and stderr of child processes
    ChildOutput { name: Name, fd: i32, line: String },
    /// Notification events
    Notification(Notification),
}

/// Result of a Runtime action
pub type RuntimeResult = Result<(), Error>;

/// Handle to the Northstar runtime
pub struct Runtime {
    /// Channel receive a stop signal for the runtime
    /// Drop the tx part to gracefully shutdown the mail loop.
    stop: Option<oneshot::Sender<()>>,
    // Channel to signal the runtime exit status to the caller of `start`
    // When the runtime is shut down the result of shutdown is sent to this
    // channel. If a error happens during normal operation the error is also
    // sent to this channel.
    stopped: oneshot::Receiver<RuntimeResult>,
    event_tx: mpsc::Sender<Event>,
}

impl Runtime {
    pub async fn start(config: Config) -> Result<Runtime, Error> {
        let (stop_tx, stop_rx) = oneshot::channel();
        let (stopped_tx, stopped_rx) = oneshot::channel();

        // Initialize minijails static functionality
        minijail_init().await?;

        // Ensure the configured run_dir exists
        mkdir_p_rw(&config.directories.data_dir).await?;
        mkdir_p_rw(&config.directories.run_dir).await?;

        // Northstar runs in a event loop. Moduls get a Sender<Event> to the main loop.
        let (event_tx, event_rx) = mpsc::channel::<Event>(100);

        // Start a task that drives the main loop and wait for shutdown results
        {
            let event_tx = event_tx.clone();
            task::spawn(async move {
                stopped_tx
                    .send(runtime_task(config, event_tx, event_rx, stop_rx).await)
                    .ok(); // Ignore error if calle dropped the handle
            });
        }

        Ok(Runtime {
            stop: Some(stop_tx),
            stopped: stopped_rx,
            event_tx,
        })
    }

    /// Stop the runtime
    pub fn stop(mut self) {
        // Drop the sending part of the stop handle
        self.stop.take();
    }

    /// Stop the runtime and wait for the termination
    pub fn stop_wait(mut self) -> impl Future<Output = RuntimeResult> {
        self.stop.take();
        self
    }

    /// Send a request to the runtime directly
    pub async fn request(&self, request: api::Request) -> Result<api::Response, Error> {
        let (response_tx, response_rx) = oneshot::channel::<api::Message>();

        let request = api::Message::new(api::Payload::Request(request));
        self.event_tx
            .send(Event::Console(
                console::Request::Message(request),
                response_tx,
            ))
            .await
            .ok();

        match response_rx.await.ok().map(|message| message.payload) {
            Some(api::Payload::Response(response)) => Ok(response),
            Some(_) => unreachable!(),
            None => panic!("Internal channel error"),
        }
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

async fn runtime_task(
    config: Config,
    event_tx: mpsc::Sender<Event>,
    mut event_rx: mpsc::Receiver<Event>,
    stop: oneshot::Receiver<()>,
) -> Result<(), Error> {
    let mut state = State::new(&config, event_tx.clone()).await?;

    // Iterate all files in SETTINGS.directories.container_dirs and try
    // to mount the content.
    for registry in &config.directories.container_dirs {
        let mounted_containers = mount::mount_npk_dir(
            &config.directories.run_dir,
            &state.signing_keys,
            &config.devices.device_mapper_dev,
            &config.devices.device_mapper,
            &config.devices.loop_control,
            &config.devices.loop_dev,
            &registry,
        )
        .await
        .map_err(Error::Mount)?;

        for container in mounted_containers {
            state.add(container)?;
        }
    }

    info!(
        "Mounted {} containers",
        state.applications.len() + state.resources.len()
    );

    // Autostart flagged containers. Each container with the `autostart` option
    // set to true in the manifest is started.
    let autostart_apps = state
        .applications
        .values()
        .filter(|app| app.manifest().autostart.unwrap_or_default())
        .map(|app| app.name().to_string())
        .collect::<Vec<Name>>();
    for app in &autostart_apps {
        info!("Autostarting {}", app);
        state.start(&app).await.ok();
    }

    // Initialize console
    let console = console::Console::new(&config.console_address, &event_tx);
    // Start to listen for incoming connections
    console.listen().await.map_err(Error::Console)?;

    // Wait for a external shutdown request
    let shutdown_tx = event_tx.clone();
    task::spawn(async move {
        stop.await.ok();
        shutdown_tx.send(Event::Shutdown).await.ok();
    });

    // Enter main loop
    loop {
        let result = match event_rx.recv().await.unwrap() {
            Event::ChildOutput { name, fd, line } => {
                on_child_output(&mut state, &name, fd, &line).await;
                Ok(())
            }
            // Debug console commands are handled via the main loop in order to get access
            // to the global state. Therefore the console server receives a tx handle to the
            // main loop and issues `Event::Console`. Processing of the command takes place
            // in the console module but with access to `state`.
            Event::Console(msg, txr) => {
                console.process(&mut state, &msg, txr).await;
                Ok(())
            }
            // The OOM event is signaled by the cgroup memory monitor if configured in a manifest.
            // If a out of memory condition occours this is signaled with `Event::Oom` which
            // carries the id of the container that is oom.
            Event::Oom(id) => state.on_oom(&id).await,
            // A container process existed. Check `process::wait_exit` for details.
            Event::Exit(ref name, ref exit_status) => state.on_exit(name, exit_status).await,
            // The runtime os commanded to shut down and exit.
            Event::Shutdown => break state.shutdown().await,
            // Forward notifications to console
            Event::Notification(notification) => {
                console.notification(notification).await;
                Ok(())
            }
        };

        // Break if a error happens in the runtime
        if result.is_err() {
            break result;
        }
    }
}

// TODO: Where to send this?
async fn on_child_output(state: &mut State, name: &str, fd: i32, line: &str) {
    if let Some(p) = state.application(name) {
        if let Some(p) = p.process_context() {
            debug!("[{}] {}: {}: {}", p.process().pid(), name, fd, line);
        }
    }
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

/// Initialize minijail logging
pub async fn minijail_init() -> Result<(), Error> {
    use std::{io::BufRead, os::unix::io::FromRawFd};

    #[allow(non_camel_case_types)]
    #[allow(dead_code)]
    #[repr(i32)]
    enum SyslogLevel {
        LOG_EMERG = 0,
        LOG_ALERT = 1,
        LOG_CRIT = 2,
        LOG_ERR = 3,
        LOG_WARNING = 4,
        LOG_NOTICE = 5,
        LOG_INFO = 6,
        LOG_DEBUG = 7,
        MAX = i32::MAX,
    }

    if let Some(log_level) = log::max_level().to_level() {
        let minijail_log_level = match log_level {
            Level::Error => SyslogLevel::LOG_ERR,
            Level::Warn => SyslogLevel::LOG_WARNING,
            Level::Info => SyslogLevel::LOG_INFO,
            Level::Debug => SyslogLevel::LOG_DEBUG,
            Level::Trace => SyslogLevel::MAX,
        };

        let (readfd, writefd) =
            pipe().map_err(|e| Error::Os("Failed to create pipe".to_string(), e))?;

        let pipe = unsafe { std::fs::File::from_raw_fd(readfd) };
        ::minijail::Minijail::log_to_fd(writefd, minijail_log_level as i32);

        let mut lines = std::io::BufReader::new(pipe).lines();
        task::spawn_blocking(move || {
            while let Some(Ok(line)) = lines.next() {
                // TODO: Format the logs to make them seemless
                log::log!(log_level, "{}", line);
            }
        });
    }

    Ok(())
}
