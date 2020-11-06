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

pub mod config;
pub(self) mod console;
pub mod error;
pub(self) mod keys;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub(self) mod linux;
pub(self) mod npk;
pub(self) mod process;
pub(super) mod state;

use crate::{api, api::Notification, manifest::Name, runtime::error::Error};
use config::Config;
use console::Request;
use log::*;
use process::ExitStatus;
use state::State;
use std::path::PathBuf;
use sync::mpsc;
use tokio::{fs, sync};

pub type EventTx = mpsc::Sender<Event>;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Event {
    /// Incomming command
    Console(Request, mpsc::Sender<api::Message>),
    /// A instance exited with return code
    Exit(Name, ExitStatus),
    /// Out of memory event occured
    Oom(Name),
    /// Fatal unhandleable error
    Error(Error),
    /// North shall shut down
    Shutdown,
    /// Stdout and stderr of child processes
    ChildOutput { name: Name, fd: i32, line: String },
    /// Notification events
    Notification(Notification),
}

#[derive(Clone, Debug)]
pub enum TerminationReason {
    /// Process was stopped by north. Normal exit
    Stopped,
    /// Process stopped by north because if is signalled out of memory
    OutOfMemory,
}

pub async fn run(config: &Config) -> Result<(), Error> {
    // On Linux systems north enters a mount namespace for automatic
    // umounting of npks. Next the mount propagation of the the parent
    // mount of the run dir is set to private. See linux::init for details.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    linux::init(&config).await?;

    // Northstar runs in a event loop. Moduls get a Sender<Event> to the main
    // loop.
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(100);

    let mut state = State::new(config, event_tx.clone()).await?;

    // Ensure the configured run_dir exists
    // TODO: permission check of SETTINGS.directories.run_dir
    fs::create_dir_all(&config.directories.run_dir)
        .await
        .map_err(|e| Error::Io {
            context: format!("Failed to create {}", config.directories.run_dir.display()),
            error: e,
        })?;

    // Ensure the configured data_dir exists
    fs::create_dir_all(&config.directories.data_dir)
        .await
        .map_err(|e| Error::Io {
            context: format!("Failed to create {}", config.directories.data_dir.display()),
            error: e,
        })?;

    // Iterate all files in SETTINGS.directories.container_dirs and try
    // to load/install the npks.
    for d in &config.directories.container_dirs {
        let d: PathBuf = d.into();
        npk::install_all(&mut state, &d.as_path())
            .await
            .map_err(Error::Installation)?;
    }

    info!(
        "Installed and loaded {} containers",
        state.applications.len()
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
        if let Err(e) = state.start(&app).await {
            warn!("Failed to start {}: {}", app, e);
        }
    }

    // Initialize console
    let console = console::Console::new(&config.console_address, &event_tx);
    // Start to listen for incoming connections
    console.listen().await?;

    // Enter main loop
    while let Some(event) = event_rx.recv().await {
        match event {
            Event::ChildOutput { name, fd, line } => {
                on_child_output(&mut state, &name, fd, &line).await
            }
            // Debug console commands are handled via the main loop in order to get access
            // to the global state. Therefore the console server receives a tx handle to the
            // main loop and issues `Event::Console`. Processing of the command takes place
            // in the console module but with access to `state`.
            Event::Console(msg, txr) => console.process(&mut state, &msg, txr).await,
            // The OOM event is signaled by the cgroup memory monitor if configured in a manifest.
            // If a out of memory condition occours this is signaled with `Event::Oom` which
            // carries the id of the container that is oom.
            Event::Oom(id) => state.on_oom(&id).await?,
            // A container process existed. Check `process::wait_exit` for details.
            Event::Exit(ref name, ref exit_status) => state.on_exit(name, exit_status).await?,
            // The runtime os commanded to shut down and exit.
            Event::Shutdown => break,
            // Forward notifications to console
            Event::Notification(notification) => console.notification(notification).await?,
            // Handle unrecoverable errors by logging it and do a gracefull shutdown.
            Event::Error(ref error) => {
                error!("Fatal error: {}", error);
                break;
            }
        }
    }

    info!("Shutting down...");

    Ok(())
}

/// This is a starting point for doing something meaningful with the childs outputs.
async fn on_child_output(state: &mut State, name: &str, fd: i32, line: &str) {
    if let Some(p) = state.application(name) {
        if let Some(p) = p.process_context() {
            debug!("[{}] {}: {}: {}", p.process().pid(), name, fd, line);
        }
    }
}
