//! Northstar runtime example main

#![deny(clippy::all)]
#![deny(missing_docs)]

use anyhow::{anyhow, Context, Error};
use clap::Parser;
use log::{debug, info, warn};
use nix::{
    mount::{mount, MsFlags},
    sched::unshare,
};
use northstar_runtime::{runtime, runtime::Runtime as Northstar};
use runtime::config::Config;
use std::{
    env,
    fs::{self, read_to_string},
    panic,
    path::{Path, PathBuf},
    process::exit,
};
use tokio::{select, signal::unix::SignalKind};

mod logger;

/// Northstar Runtime
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
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

fn main() -> Result<(), Error> {
    // Replace /proc/self/exe with a memfd. See [1] why. This is *not* needed if
    // the runtime binary is invoked from a secure and read only storage location.
    // [1] https://github.com/lxc/lxc/commit/6400238d08cdf1ca20d49bafb85f4e224348bf9d
    // northstar_runtime::rexec()?;

    // Initialize logging
    logger::init();

    info!("Northstar Runtime v{}", env!("CARGO_PKG_VERSION"));
    debug!(
        "Running as user {} (uid: {})",
        env::var("USER").unwrap_or_else(|_| "unknown".into()),
        env::var("UID").unwrap_or_else(|_| "unknown".into())
    );

    // Install a custom panic hook that aborts the process in case of a panic *anywhere*
    let default_panic = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        default_panic(info);
        exit(1);
    }));

    // Parse command line arguments and prepare the environment
    let config = init()?;

    // Create the runtime launcher. This must be done *before* spawning the tokio threadpool.
    let northstar = Northstar::new(config)?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("northstar")
        .build()
        .context("failed to create runtime")?
        .block_on(run(northstar))
}

fn init() -> Result<Config, Error> {
    let opt = Opt::parse();
    let config = read_to_string(&opt.config)
        .with_context(|| format!("failed to read configuration file {}", opt.config.display()))?;
    let config: Config = toml::from_str(&config)
        .with_context(|| format!("failed to read configuration file {}", opt.config.display()))?;

    fs::create_dir_all(&config.run_dir).context("failed to create run_dir")?;
    fs::create_dir_all(&config.data_dir).context("failed to create data_dir")?;
    fs::create_dir_all(&config.log_dir).context("failed to create log dir")?;

    // Skip mount namespace setup in case it's disabled for debugging purposes
    if !opt.disable_mount_namespace {
        // Enter a mount namespace. This needs to be done before spawning the tokio threadpool.
        info!("Entering mount namespace");
        unshare(nix::sched::CloneFlags::CLONE_NEWNS)?;

        // The mount propagation can be set to the root dir because this is done in the mount namespace
        // that is created above and does not affect the rest of the host system.
        debug!("Setting mount propagation to MS_PRIVATE on /");
        let flags = MsFlags::MS_PRIVATE | MsFlags::MS_REC;
        let root = Path::new("/");
        let none = Option::<&str>::None;
        mount(Some(root), root, none, flags, none)
            .map_err(|_| anyhow!("failed to remount root"))?;
    } else {
        debug!("Mount namespace is disabled");
    }

    Ok(config)
}

async fn run(northstar: Northstar) -> Result<(), Error> {
    let mut runtime = northstar
        .start()
        .await
        .context("failed to start Northstar")?;

    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())
        .context("failed to install sigint handler")?;
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())
        .context("failed to install sigterm handler")?;
    let mut sighup = tokio::signal::unix::signal(SignalKind::hangup())
        .context("failed to install sighup handler")?;

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
        status = runtime.stopped() => status,
    };

    match status {
        Ok(_) => exit(0),
        Err(e) => {
            warn!("Runtime exited with {:?}", e);
            exit(1);
        }
    }
}
