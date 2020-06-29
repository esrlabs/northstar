// Copyright (c) 2020 E.S.R.Labs. All rights reserved.
//
// NOTICE:  All information contained herein is, and remains
// the property of E.S.R.Labs and its suppliers, if any.
// The intellectual and technical concepts contained herein are
// proprietary to E.S.R.Labs and its suppliers and may be covered
// by German and Foreign Patents, patents in process, and are protected
// by trade secret or copyright law.
// Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained
// from E.S.R.Labs.

#![deny(clippy::all)]

#[cfg(any(target_os = "android", target_os = "linux"))]
#[macro_use]
extern crate structure;

use anyhow::{Context, Error, Result};
use async_std::{fs, sync};
use log::*;

mod cgroups;
mod console;
mod container;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod linux;
mod process;
mod settings;
mod state;
mod update;

pub const SYSTEM_UID: u32 = 1000;
pub const SYSTEM_GID: u32 = 1000;

// Reexport SETTINGS for mods
pub use settings::SETTINGS;
pub use state::State;

pub type Name = String;
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

    #[cfg(any(target_os = "android", target_os = "linux"))]
    linux::setup().await?;

    let (tx, rx) = sync::channel::<Event>(1000);
    let mut state = State::new(tx.clone());

    fs::create_dir_all(&SETTINGS.run_dir)
        .await
        .with_context(|| format!("Failed to create {}", SETTINGS.run_dir.display()))?;
    fs::create_dir_all(&SETTINGS.data_dir)
        .await
        .with_context(|| format!("Failed to create {}", SETTINGS.data_dir.display()))?;

    for d in &SETTINGS.container_dirs {
        container::install_all(&mut state, d).await?;
    }

    info!(
        "Installed and loaded {} containers",
        state.applications.len()
    );

    // Initialize console
    console::init(&tx).await?;

    // Autostart flagged containers
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
    while let Some(event) = rx.recv().await {
        match event {
            Event::Console(cmd, txr) => console::process(&mut state, &cmd, txr).await?,
            Event::Oom(id) => state.on_oom(&id).await?,
            Event::Exit(ref name, return_code) => state.on_exit(name, return_code).await?,
            Event::Error(ref error) => {
                error!("Fatal error: {}", error);
                break;
            }
            Event::Shutdown => break,
        }
    }

    info!("Shutting down...");

    Ok(())
}
