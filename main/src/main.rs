//! Northstar runtime example main

#![deny(clippy::all)]
#![deny(missing_docs)]

use anyhow::{anyhow, Context, Error};
use clap::Parser;
use log::{debug, info, warn};
use nix::mount::MsFlags;
use northstar::runtime;
use runtime::config::Config;
use std::{
    fs::{self, read_to_string},
    path::{Path, PathBuf},
    process::exit,
};
use tokio::{select, signal::unix::SignalKind};

mod logger;

#[derive(Debug, Parser)]
#[clap(name = "northstar", about = "Northstar")]
struct Opt {
    /// File that contains the northstar configuration
    #[clap(short, long, default_value = "northstar.toml")]
    pub config: PathBuf,

    /// Do not enter a mount namespace if this option is set Be aware that in
    /// case of a non normal termination of the runtime the images mounted in
    /// `run_dir` have to be umounted manually before starting the runtime again.
    #[clap(short, long)]
    pub disable_mount_namespace: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let opt = Opt::parse();
    let config = read_to_string(&opt.config)
        .with_context(|| format!("Failed to read configuration file {}", opt.config.display()))?;
    let config: Config = toml::from_str(&config)
        .with_context(|| format!("Failed to read configuration file {}", opt.config.display()))?;

    logger::init();

    fs::create_dir_all(&config.run_dir).context("Failed to create run_dir")?;
    fs::create_dir_all(&config.data_dir).context("Failed to create data_dir")?;
    fs::create_dir_all(&config.log_dir).context("Failed to create log dir")?;

    // Skip mount namespace setup in case it's disabled for debugging purposes
    if !opt.disable_mount_namespace {
        // Enter a mount namespace. This needs to be done before spawning the tokio threadpool.
        info!("Entering mount namespace");
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)?;

        // The mount propagation can be set to the root dir because this is done in the mount namespace
        // that is created above and does not affect the rest of the host system.
        debug!("Setting mount propagation to MS_PRIVATE on /");
        let flags = MsFlags::MS_PRIVATE | MsFlags::MS_REC;
        let root = Path::new("/");
        let none = Option::<&str>::None;
        nix::mount::mount(Some(root), root, none, flags, none)
            .map_err(|_| anyhow!("Failed to remount root"))?;
    } else {
        debug!("Mount namespace is disabled");
    }

    let mut runtime = runtime::Runtime::start(config)
        .await
        .context("Failed to start runtime")?;
    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())
        .context("Failed to install sigint handler")?;
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())
        .context("Failed to install sigterm handler")?;
    let mut sighup = tokio::signal::unix::signal(SignalKind::hangup())
        .context("Failed to install sighup handler")?;

    let status = select! {
        _ = sigint.recv() => {
            info!("Received SIGINT. Stopping Northstar runtime");
            runtime.shutdown().await
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM. Stopping Northstar runtime");
            runtime.shutdown().await
        }
        _ = sighup.recv() => {
            info!("Received SIGHUP. Stopping Northstar runtime");
            runtime.shutdown().await
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
