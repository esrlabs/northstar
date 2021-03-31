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
use tokio::{task, time};

#[tokio::main]
async fn main() -> Result<()> {
    // Umount after each stop
    let umount = false;

    // Get a list of installed applications
    let url = url::Url::parse("tcp://localhost:4200").unwrap();
    let client = client::Client::new(&url).await?;
    let mut apps = client
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

    for (app, version) in apps.drain(..) {
        let url = url.clone();
        let task = task::spawn(async move {
            let client = client::Client::new(&url).await?;
            loop {
                client.start(&app, &version).await?;

                client
                    .stop(&app, &version, time::Duration::from_secs(5))
                    .await
                    .ok();

                if umount {
                    client.umount(&app, &version).await?;
                }
            }
        })
        .then(|r| match r {
            Ok(r) => ready(r),
            Err(e) => ready(Result::<()>::Err(anyhow::anyhow!("task error: {}", e))),
        });
        tasks.push(task);
    }

    try_join_all(tasks).await.map(drop)
}
