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

#![deny(clippy::all)]

#[cfg(any(target_os = "android", target_os = "linux"))]
#[macro_use]
extern crate structure;

use anyhow::{Context, Error, Result};
use async_std::{fs, path::PathBuf, prelude::*, sync};
use ed25519_dalek::PublicKey;
use log::*;
use nix::unistd::{self, chown};
use north_common::manifest::Name;
use std::collections::HashMap;

mod console;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod linux;
mod npk;
mod process;
mod settings;
mod state;
mod update;

pub const SYSTEM_UID: u32 = 1000;
pub const SYSTEM_GID: u32 = 1000;

// Reexport SETTINGS for mods
pub use settings::SETTINGS;
pub use state::State;

pub type EventTx = sync::Sender<Event>;
#[allow(clippy::large_enum_variant)]
pub enum Event {
    /// Incomming console command
    Console(String, sync::Sender<String>),
    /// A instance exited with return code
    Exit(Name, i32),
    /// Out of memory event occured
    Oom(Name),
    /// Fatal unhandleable error
    Error(Error),
    /// North shall shut down
    Shutdown,
    /// Stdout and stderr of child processes
    ChildOutput { name: Name, fd: i32, line: String },
}

#[derive(Clone, Debug)]
pub enum TerminationReason {
    /// Process was stopped by north. Normal exit
    Stopped,
    /// Process stopped by north because if is signalled out of memory
    OutOfMemory,
}

#[async_std::main]
async fn main() -> Result<()> {
    let filter = if SETTINGS.debug {
        "north=debug"
    } else {
        "north=info"
    };
    logd_logger::builder()
        .parse_filters(filter)
        .tag("north")
        .init();

    info!(
        "North v{} ({})",
        env!("VERGEN_SEMVER"),
        env!("VERGEN_SHA_SHORT")
    );

    trace!("Settings: {}", *SETTINGS);

    // On Linux systems north enters a mount namespace for automatic
    // umounting of npks. Next the mount propagation of the the parent
    // mount of the run dir is set to private. See linux::init for details.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    linux::init().await?;

    let signing_keys = load_signing_keys(&SETTINGS.directories.key_dir).await?;

    // Northstar runs in a event loop. Moduls get a Sender<Event> to the main
    // loop.
    let (tx, rx) = sync::channel::<Event>(1000);
    let mut state = State::new(tx.clone(), signing_keys);

    // Ensure the configured run_dir exists
    // TODO: permission check of SETTINGS.directories.run_dir
    fs::create_dir_all(&SETTINGS.directories.run_dir)
        .await
        .with_context(|| {
            format!(
                "Failed to create {}",
                SETTINGS.directories.run_dir.display()
            )
        })?;

    // Ensure the configured data_dir exists
    fs::create_dir_all(&SETTINGS.directories.data_dir)
        .await
        .with_context(|| {
            format!(
                "Failed to create {}",
                SETTINGS.directories.data_dir.display()
            )
        })?;

    // The SETTINGS.global_data_dir option makes north using a single directory
    // that is bind mounted into the roots of the containers. In normal operation
    // each container get's it's own read and writeable data directory for
    // persistent data.
    if SETTINGS.global_data_dir {
        let data: &std::path::Path = SETTINGS.directories.data_dir.as_path().into();
        chown(
            data,
            Some(unistd::Uid::from_raw(SYSTEM_UID)),
            Some(unistd::Gid::from_raw(SYSTEM_GID)),
        )
        .with_context(|| {
            format!(
                "Failed to chown {} to {}:{}",
                data.display(),
                SYSTEM_UID,
                SYSTEM_GID
            )
        })?;
    }

    // Iterate all files in SETTINGS.directories.container_dirs and try
    // to load/install the npks.
    for d in &SETTINGS.directories.container_dirs {
        npk::install_all(&mut state, d).await?;
    }

    info!(
        "Installed and loaded {} containers",
        state.applications.len()
    );

    // Initialize console
    console::init(&tx).await?;

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
        if let Err(e) = state.start(&app, 0).await {
            warn!("Failed to start {}: {}", app, e);
        }
    }

    // Enter main loop
    while let Ok(event) = rx.recv().await {
        match event {
            Event::ChildOutput { name, fd, line } => on_child_output(&mut state, &name, fd, &line),
            // Debug console commands are handled via the main loop in order to get access
            // to the global state. Therefore the console server receives a tx handle to the
            // main loop and issues `Event::Console`. Processing of the command takes place
            // in the console module again but with access to `state`.
            Event::Console(cmd, txr) => console::process(&mut state, &cmd, txr).await?,
            // The OOM event is signaled by the cgroup memory monitor if configured in a manifest.
            // If a out of memory condition occours this is signaled with `Event::Oom` which
            // carries the id of the container that is oom.
            Event::Oom(id) => state.on_oom(&id).await?,
            // A container process existed. Check `process::wait_exit` for details.
            Event::Exit(ref name, return_code) => state.on_exit(name, return_code).await?,
            // Handle unrecoverable errors by logging it and do a gracefull shutdown.
            Event::Error(ref error) => {
                error!("Fatal error: {}", error);
                break;
            }
            // The runtime os commanded to shut down and exit.
            Event::Shutdown => break,
        }
    }

    info!("Shutting down...");

    Ok(())
}

async fn load_signing_keys(key_dir: &PathBuf) -> Result<HashMap<String, PublicKey>> {
    let mut signing_keys = HashMap::new();
    let mut key_dir = fs::read_dir(&key_dir).await?;
    while let Some(entry) = key_dir.next().await {
        let entry = entry?;
        let path = entry.path();
        if let Some(extension) = path.extension() {
            if extension == "pub" && path.is_file().await {
                if let Some(key_id) = path.file_stem() {
                    let mut sign_key_file = fs::File::open(&path).await?;
                    let mut key_bytes = Vec::new();
                    sign_key_file.read_to_end(&mut key_bytes).await?;
                    let key = PublicKey::from_bytes(&key_bytes)?;
                    signing_keys.insert(key_id.to_string_lossy().to_string(), key);
                    info!("Loaded signing key {:?}", key_id);
                }
            }
        }
    }
    Ok(signing_keys)
}

/// This is a starting point for doing something meaningful with the childs outputs.
fn on_child_output(state: &mut State, name: &str, fd: i32, line: &str) {
    if let Some(p) = state.application(name) {
        if let Some(p) = p.process_context() {
            debug!("[{}] {}: {}: {}", p.process().pid(), name, fd, line);
        }
    }
}
