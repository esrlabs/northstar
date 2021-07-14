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
use futures::StreamExt;
use northstar::api::client::Client;
use tokio::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // In the manifest the northstar management mount is mapped to /northstar
    let url = url::Url::parse("unix:///northstar/console")?;
    println!("Connecting to northstar on {}", url);

    // Connect a client with notifications enabled
    let mut client = Client::new(&url, Some(10), Duration::from_secs(5)).await?;

    println!("Connected to northstar on {}", url);

    println!("Waiting for notifications");
    while let Some(Ok(n)) = client.next().await {
        println!("Received Northstar notification {:?}", n);
    }
    Ok(())
}
