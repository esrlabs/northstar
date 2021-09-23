//! Northstar runtime example main

#![deny(clippy::all)]
#![deny(missing_docs)]

use anyhow::{anyhow, Context, Error};
use log::{debug, info, warn};
use northstar::runtime;
use proc_mounts::MountIter;
use runtime::config::Config;
use std::{
    collections::HashSet,
    fs::{self, read_to_string},
    path::{Path, PathBuf},
    process::exit,
};
use structopt::StructOpt;
use tokio::{select, signal::unix::SignalKind};

mod logger;

#[derive(Debug, StructOpt)]
#[structopt(name = "northstar", about = "Northstar")]
struct Opt {
    /// File that contains the northstar configuration
    #[structopt(short, long, default_value = "northstar.toml")]
    pub config: PathBuf,

    /// Do not enter a mount namespace if this option is set Be aware that in
    /// case of a non normal termination of the runtime the images mounted in
    /// `run_dir` have to be umounted manually before starting the runtime again.
    #[structopt(short, long)]
    pub disable_mount_namespace: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let opt = Opt::from_args();
    let config = read_to_string(&opt.config)
        .with_context(|| format!("Failed to read configuration file {}", opt.config.display()))?;
    let config: Config = toml::from_str(&config)
        .with_context(|| format!("Failed to read configuration file {}", opt.config.display()))?;

    logger::init();

    fs::create_dir_all(&config.run_dir).context("Failed to create run_dir")?;
    fs::create_dir_all(&config.data_dir).context("Failed to create data_dir")?;
    fs::create_dir_all(&config.log_dir).context("Failed to create log dir")?;

    let mut run_dir_mount = None;
    // Skip mount namespace setup in case it's disabled for debugging purposes
    if !opt.disable_mount_namespace {
        // Enter a mount namespace. This needs to be done before spawning the tokio threadpool.
        info!("Entering mount namespace");
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)?;

        if !is_mount_point(&config.run_dir)? {
            debug!("Bind mounting {}", config.run_dir.display());
            nix::mount::mount(
                Some(&config.run_dir),
                config.run_dir.as_os_str(),
                Option::<&str>::None,
                nix::mount::MsFlags::MS_BIND,
                Option::<&'static [u8]>::None,
            )
            .map_err(|_| anyhow!("Failed to bind mount run_dir"))?;
            run_dir_mount = Some(config.run_dir.clone());
        } else {
            debug!(
                "Using existing run_dir mountpoint {}",
                config.run_dir.display()
            );
        }

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
        .map_err(|_| anyhow!("Failed to remount run_dir"))?;
    } else {
        warn!("Mount namespace is disabled");
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

    if let Some(run_dir) = run_dir_mount {
        nix::mount::umount(&run_dir).map_err(|_| anyhow!("Failed to umount run_dir"))?;
    }

    match status {
        Ok(_) => exit(0),
        Err(e) => {
            warn!("Runtime exited with {:?}", e);
            exit(1);
        }
    }
}

/// Returns true if `dir` is a mountpoint listed in /proc/self/mounts
fn is_mount_point(dir: &Path) -> Result<bool, Error> {
    let mounts = MountIter::new().map_err(|_| anyhow!("Failed to read mounts"))?;
    let mountpoints = mounts
        .filter_map(Result::ok)
        .map(|m| m.dest)
        .collect::<HashSet<_>>();
    let run_dir = std::fs::canonicalize(&dir).map_err(|_| anyhow!("Canonicalize path"))?;
    Ok(mountpoints.contains(&run_dir))
}
