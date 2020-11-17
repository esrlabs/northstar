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

use anyhow::{Context, Error};
use log::{info, warn};
use north::runtime;
use runtime::config::Config;
use std::{env, fs::read_to_string, path::PathBuf, process::exit};
use structopt::StructOpt;
use tokio::{select, signal::unix::SignalKind};

#[derive(Debug, StructOpt)]
#[structopt(name = "north", about = "Northstar")]
struct Opt {
    /// File that contains the north configuration
    #[structopt(short, long, default_value = "north.toml")]
    pub config: PathBuf,

    #[structopt(short, long)]
    /// Print debug logs
    pub debug: bool,
}

fn main() -> Result<(), Error> {
    let opt = Opt::from_args();
    let config = read_to_string(&opt.config)
        .with_context(|| format!("Failed to read configuration file {}", opt.config.display()))?;
    let config: Config = toml::from_str(&config)
        .with_context(|| format!("Failed to read configuration file {}", opt.config.display()))?;

    let log_filter = if opt.debug || config.debug {
        "north=debug"
    } else {
        "north=info"
    };
    {
        logd_logger::builder()
            .parse_filters(log_filter)
            .tag("north")
            .init();
    }

    info!(
        "North v{} ({})",
        env!("VERGEN_SEMVER"),
        env!("VERGEN_SHA_SHORT")
    );

    // Set the mount propagation of unshare_root to MS_PRIVATE
    nix::mount::mount(
        Option::<&'static [u8]>::None,
        config.devices.unshare_root.as_os_str(),
        Some(config.devices.unshare_fstype.as_str()),
        nix::mount::MsFlags::MS_PRIVATE,
        Option::<&'static [u8]>::None,
    )?;

    // Enter a mount namespace. This needs to be done before spawning
    // the tokio threadpool.
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("northstar")
        .build()?;
    runtime.block_on(run(config))
}

async fn run(config: Config) -> Result<(), Error> {
    let mut runtime = runtime::Runtime::start(config)
        .await
        .context("Failed to start runtime")?;
    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())
        .context("Failed to install sigint handler")?;
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())
        .context("Failed to install sigterm handler")?;

    let status = select! {
        _ = sigint.recv() => {
            info!("Received SIGINT. Stopping Northstar runtime");
            runtime.stop_wait().await
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM. Stopping Northstar runtime");
            runtime.stop_wait().await
        }
        status = &mut runtime => status,
    };
    match status {
        Ok(_) => exit(0),
        Err(e) => {
            warn!("Runtime exited with {:?}", e);
            exit(1);
        }
    }
}
