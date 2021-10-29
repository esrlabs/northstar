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
use northstar::api::client;
use std::{env, os::unix::prelude::FromRawFd, time::Duration};
use tokio::net::UnixStream;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Gather fd number from env
    let fd = env::var("NORTHSTAR_CONSOLE")?.parse::<i32>()?;

    println!("Console fd is {}", fd);

    // Wrap fd in UnixStream which is used as io object for the client
    let std = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    std.set_nonblocking(true)?;
    let io = UnixStream::from_std(std)?;

    println!("Connecting...");

    // Instantiate client and start connect sequence
    let mut client = client::Client::new(io, None, Duration::from_secs(5)).await?;

    for container in client.containers().await? {
        println!(
            "{} is {}",
            container.container,
            container
                .process
                .map(|_| "started")
                .unwrap_or_else(|| "stopped")
        );
    }

    // Send signal 15 to ourself
    client.kill("console:0.0.1", 15).await?;

    // Wait for the sigterm
    tokio::time::sleep(tokio::time::Duration::from_secs(u64::MAX)).await;

    Ok(())
}
