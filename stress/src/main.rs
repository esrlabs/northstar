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

use anyhow::Result;
use futures::{
    future::{ready, try_join_all},
    FutureExt,
};
use northstar::api::client;
use structopt::StructOpt;
use tokio::{select, task, time};
use tokio_util::sync::CancellationToken;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "stress",
    about = "Manual stress test the start and stop of Nortstar containers"
)]
struct Opt {
    /// Runtime address
    #[structopt(short, long, default_value = "tcp://localhost:4200")]
    address: url::Url,
    /// Umount container after stopping
    #[structopt(short, long)]
    umount: bool,

    /// Duration to run the test for in seconds
    #[structopt(short, long)]
    duration: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();

    // Get a list of installed applications
    let client = client::Client::new(&opt.address).await?;
    let apps = client
        .containers()
        .await?
        .iter()
        .filter(|c| c.manifest.init.is_some())
        .map(|c| (c.manifest.name.to_string(), c.manifest.version.clone()))
        .collect::<Vec<_>>();
    for (app, version) in &apps {
        client
            .stop(&app, &version, time::Duration::from_secs(5))
            .await
            .ok();
    }
    drop(client);

    let mut tasks = Vec::new();
    let token = CancellationToken::new();

    for (app, version) in apps.clone().drain(..) {
        let token = token.clone();
        let url = opt.address.clone();
        let umount = opt.umount;

        let task = task::spawn(async move {
            let client = client::Client::new(&url).await?;
            loop {
                // Start the container
                client.start(&app, &version).await?;

                // Ignore errors on stop because some containers just do something and exit
                // See for example the datarw example container
                client
                    .stop(&app, &version, time::Duration::from_secs(5))
                    .await
                    .ok();

                if umount {
                    client.umount(&app, &version).await?;
                }
                if token.is_cancelled() {
                    break Ok(());
                }
            }
        })
        .then(|r| match r {
            Ok(r) => ready(r),
            Err(e) => ready(Result::<()>::Err(anyhow::anyhow!("task error: {}", e))),
        });
        tasks.push(task);
    }

    let mut tasks = try_join_all(tasks);

    if let Some(duration) = opt.duration {
        select! {
            _ = time::sleep(time::Duration::from_secs(duration)) => {
                token.cancel();
                tasks.await.map(drop)
            }
            r = &mut tasks => r.map(drop),
        }
    } else {
        tasks.await.map(drop)
    }
}
