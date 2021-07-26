// Copyright (c) 2021 ESRLabs
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

use anyhow::{anyhow, Context, Result};
use futures::{
    future::{self, pending, ready, try_join_all},
    FutureExt, StreamExt,
};
use log::{debug, info};
use northstar::api::{
    client::{self, Client},
    model::{self, ExitStatus, Notification},
};
use std::{path::PathBuf, str::FromStr};
use structopt::StructOpt;
use tokio::{pin, select, task, time};
use tokio_util::{either::Either, sync::CancellationToken};

#[derive(Clone, Debug, PartialEq)]
enum Mode {
    MountUmount,
    StartStop,
    StartStopUmount,
    MountStartStopUmount,
    InstallUninstall,
}

impl FromStr for Mode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mount-umount" => Ok(Mode::MountUmount),
            "start-stop" => Ok(Mode::StartStop),
            "start-stop-umount" => Ok(Mode::StartStopUmount),
            "mount-start-stop-umount" => Ok(Mode::StartStopUmount),
            "install-uninstall" => Ok(Mode::InstallUninstall),
            _ => Err("Invalid mode"),
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "stress",
    about = "Manual stress test the start and stop of Nortstar containers"
)]
struct Opt {
    /// Runtime address
    #[structopt(short, long, default_value = "tcp://localhost:4200")]
    address: url::Url,

    /// Duration to run the test for in seconds
    #[structopt(short, long)]
    duration: Option<u64>,

    /// Random delay between each iteration within 0..value ms
    #[structopt(short, long)]
    random: Option<u64>,

    /// Mode
    #[structopt(short, long, default_value = "start-stop")]
    mode: Mode,

    /// Npk for install-uninstall mode
    #[structopt(long, required_if("mode", "install-uninstall"))]
    npk: Option<PathBuf>,

    /// Repository for install-uninstall mode
    #[structopt(long, required_if("mode", "install-uninstall"))]
    repository: Option<String>,

    /// Relaxed result
    #[structopt(long)]
    relaxed: bool,

    /// Initial random delay in ms to randomize tasks
    #[structopt(long)]
    initial_random_delay: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::from_args();
    let timeout = time::Duration::from_secs(30);

    info!("mode: {:?}", opt.mode);
    info!("duration: {:?}", opt.duration);
    debug!("address: {}", opt.address.to_string());
    debug!("repository: {:?}", opt.repository);
    debug!("npk: {:?}", opt.npk);
    debug!("relaxed: {}", opt.relaxed);
    debug!("random: {:?}", opt.random);

    if opt.mode == Mode::InstallUninstall {
        return install_uninstall(&opt).await;
    }

    // Get a list of installed applications
    debug!("Getting list of startable containers");
    let mut client = client::Client::new(&opt.address, None, timeout).await?;
    let containers = client
        .containers()
        .await?
        .iter()
        .filter(|c| c.manifest.init.is_some())
        .map(|c| c.container.clone())
        .collect::<Vec<_>>();
    drop(client);

    let mut tasks = Vec::new();
    let token = CancellationToken::new();

    // Check random value that cannot be 0
    if let Some(delay) = opt.random {
        if delay == 0 {
            panic!("Invalid random value");
        }
    }

    // Max string len of all containers
    let len = containers
        .iter()
        .map(ToString::to_string)
        .map(|s| s.len())
        .sum::<usize>();

    let start = CancellationToken::new();

    for container in &containers {
        let container = container.clone();
        let initial_random_delay = opt.initial_random_delay;
        let mode = opt.mode.clone();
        let random = opt.random;
        let relaxed = opt.relaxed;
        let start = start.clone();
        let token = token.clone();
        let url = opt.address.clone();

        debug!("Spawning task for {}", container);
        let task = task::spawn(async move {
            start.cancelled().await;
            if let Some(initial_delay) = initial_random_delay {
                time::sleep(time::Duration::from_millis(
                    rand::random::<u64>() % initial_delay,
                ))
                .await;
            }

            let notifications = if relaxed { None } else { Some(100) };
            let mut client = client::Client::new(&url, notifications, timeout).await?;
            let mut iterations = 0;
            loop {
                if mode == Mode::MountStartStopUmount || mode == Mode::MountUmount {
                    info!("{:<a$} mount", &container, a = len);
                    client.mount(vec![container.clone()]).await?;
                }

                if mode != Mode::MountUmount {
                    info!("{:<a$}: start", container, a = len);
                    client.start(&container).await?;
                    if !relaxed {
                        let started = Notification::Started(container.clone());
                        await_notification(&mut client, started, 60).await?;
                    }
                }

                if let Some(delay) = random {
                    let delay = time::Duration::from_millis(rand::random::<u64>() % delay);
                    info!("{:<a$}: sleeping for {:?}", container, delay, a = len);
                    time::sleep(delay).await;
                }

                if mode != Mode::MountUmount {
                    info!("{:<a$}: stopping", container, a = len);
                    client
                        .stop(container.clone(), time::Duration::from_secs(5))
                        .await
                        .context("Failed to stop container")?;

                    if !relaxed {
                        info!("{:<a$}: waiting for termination", container, a = len);
                        let stopped =
                            Notification::Stopped(container.clone(), ExitStatus::Signaled(15));
                        await_notification(&mut client, stopped, 60).await?;
                    }
                }

                // Check if we need to umount
                if mode != Mode::StartStop {
                    info!("{:<a$}: umounting", container, a = len);
                    client
                        .umount(container.clone())
                        .await
                        .context("Failed to umount")?;
                }

                iterations += 1;
                if token.is_cancelled() {
                    info!("{:<a$}: finishing", container, a = len);
                    drop(client);
                    break Ok(iterations);
                }
            }
        })
        .then(|r| match r {
            Ok(r) => ready(r),
            Err(e) => ready(Result::<u32>::Err(anyhow!("task error: {}", e))),
        });
        tasks.push(task);
    }

    info!("Starting {} tasks", containers.len());
    start.cancel();

    let mut tasks = try_join_all(tasks);
    let ctrl_c = tokio::signal::ctrl_c();
    let duration = opt
        .duration
        .map(time::Duration::from_secs)
        .map(time::sleep)
        .map(Either::Left)
        .unwrap_or_else(|| Either::Right(future::pending::<()>()));

    let result = select! {
        _ = duration => {
            info!("Stopping because test duration exceeded");
            token.cancel();
            tasks.await
        }
        _ = ctrl_c => {
            info!("Stopping because of ctrlc");
            token.cancel();
            tasks.await
        }
        r = &mut tasks => r,
    };

    info!("Total iterations: {}", result?.iter().sum::<u32>());
    Ok(())
}

/// Wait for a `notifcation` for `duration` seconds or timeout
async fn await_notification(
    client: &mut Client,
    notification: Notification,
    duration: u64,
) -> Result<()> {
    let duration = time::Duration::from_secs(duration);

    time::timeout(duration, async {
        loop {
            match client.next().await {
                Some(Ok(n)) if n == notification => break Ok(()),
                Some(Ok(_)) => continue,
                Some(Err(e)) => break Err(e.into()),
                None => break Err(anyhow!("Notification stream closed")),
            }
        }
    })
    .await
    .context("Failed to wait for notification")?
}

/// Install and uninstall an npk in a loop
async fn install_uninstall(opt: &Opt) -> Result<()> {
    let timeout = time::Duration::from_secs(30);
    let mut client = client::Client::new(&opt.address, Some(10), timeout).await?;

    let timeout = opt
        .duration
        .map(|d| Either::Left(time::sleep(time::Duration::from_secs(d))))
        .unwrap_or_else(|| Either::Right(pending()));
    pin!(timeout);

    let npk = opt
        .npk
        .as_ref()
        .ok_or_else(|| anyhow!("Missing npk argument"))?;
    let repository = opt
        .repository
        .as_ref()
        .ok_or_else(|| anyhow!("Missing repository argument"))?;

    // Initial install - everyhing beyond is notification triggered
    client.install(npk, repository).await?;

    loop {
        select! {
            _ = &mut timeout => break Ok(()),
            n = client.next() => {
                match n {
                    Some(Ok(model::Notification::Install(container))) => {
                        client.uninstall(container).await?;
                    }
                    Some(Ok(model::Notification::Uninstall(_))) => {
                        client.install(npk, repository).await?;
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => break Err(e.into()),
                    None => break Err(anyhow!("Runtime closed the connection")),
                }
            }
        }
    }
}
