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
use northstar_client::Client;
use std::time::Duration;
use tokio::time;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Instantiate client and start connect sequence
    let mut client = Client::from_env(None, Duration::from_secs(5)).await?;

    // Request the identity of this container
    let ident = client.ident().await?;
    println!("We are {}", ident);

    // List repositories
    println!(
        "Listing repositories is denied: {:?}",
        client.repositories().await
    );

    // Iterate containers and print their names and state
    for container in client.list().await? {
        let data = client.inspect(&container).await?;
        println!(
            "{} is {}",
            container,
            data.process.map(|_| "started").unwrap_or_else(|| "stopped")
        );
    }

    // Send signal 15 to ourself
    client.kill("console:0.0.1", 15).await?;

    // Wait for the sigterm
    time::sleep(Duration::from_secs(u64::MAX)).await;

    Ok(())
}
