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
    future::{pending, ready, try_join_all},
    FutureExt, StreamExt,
};
use northstar::api::{
    client,
    model::{self, Container},
};
use std::{convert::TryInto, path::PathBuf, str::FromStr};
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

    /// Random delay between each iteration within 1..value ms
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
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::from_args();
    let timeout = time::Duration::from_secs(30);

    if opt.mode == Mode::InstallUninstall {
        return install_uninstall(&opt).await;
    }

    // Get a list of installed applications
    let mut client = client::Client::new(&opt.address, None, timeout).await?;
    let apps = client
        .containers()
        .await?
        .iter()
        .filter(|c| c.manifest.init.is_some())
        .map(|c| (c.manifest.name.to_string(), c.manifest.version.clone()))
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

    for (app, version) in apps.clone().drain(..) {
        let token = token.clone();
        let random = opt.random;
        let url = opt.address.clone();
        let mode = opt.mode.clone();
        let container = Container::new(app.clone().try_into().unwrap(), version.clone());

        let task = task::spawn(async move {
            let mut client = client::Client::new(&url, None, timeout).await?;
            let mut iterations = 0;
            loop {
                if mode == Mode::MountStartStopUmount || mode == Mode::MountUmount {
                    client.mount(Some(container.clone())).await?;
                }

                if mode != Mode::MountUmount {
                    client.start(container.clone()).await?;
                }

                if let Some(delay) = random {
                    let delay = rand::random::<u64>() % delay;
                    time::sleep(time::Duration::from_millis(delay)).await;
                }

                if mode != Mode::MountUmount {
                    client
                        .stop(container.clone(), time::Duration::from_secs(5))
                        .await
                        .context("Failed to stop container")?;
                }

                // Check if we need to umount
                if mode != Mode::StartStop {
                    client
                        .umount(container.clone())
                        .await
                        .context("Failed to umount")?;
                }

                iterations += 1;
                if token.is_cancelled() {
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

    let mut tasks = try_join_all(tasks);
    let ctrl_c = tokio::signal::ctrl_c();
    let result = if let Some(duration) = opt.duration {
        select! {
            _ = time::sleep(time::Duration::from_secs(duration)) => {
                token.cancel();
                tasks.await
            }
            _ = ctrl_c => {
                token.cancel();
                tasks.await
            }
            r = &mut tasks => r,
        }
    } else {
        select! {
            _ = ctrl_c => {
                token.cancel();
                tasks.await
            }
            r = &mut tasks => r,
        }
    };

    println!("Total iterations: {}", result?.iter().sum::<u32>());
    Ok(())
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
