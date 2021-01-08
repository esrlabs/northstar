// Copyright (c) 2020 ESRLabs
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
use futures::{future::ready, stream::once, Stream, StreamExt};
use northstar::api::{self, client::Client};
use std::{fmt::Debug, io::Write};
use structopt::StructOpt;
use tokio::{select, time};

mod pretty;
mod terminal;

/// Input type for commands
type Input = Box<dyn Stream<Item = String> + Unpin>;
/// Output
type Output = Box<dyn std::io::Write>;

#[derive(Debug, StructOpt)]
#[structopt(name = "nstar", about = "Northstar CLI")]
struct Opt {
    /// File that contains the northstar configuration
    #[structopt(short, long, default_value = "localhost:4200")]
    host: String,

    /// Optional single command to run and exit
    #[structopt(subcommand)]
    cmd: Option<Command>,
}

#[derive(Debug, StructOpt)]
enum Command {
    /// List containers
    Containers,
    /// List containers
    Ls,
    /// List repositories
    Repositories,
    /// Try to start a container with name `name`
    Start { name: Option<String> },
    /// Try to stop a container with name `name`
    Stop { name: Option<String> },
    /// Shutdown the runtime
    Shutdown,
}

impl Command {
    /// Convert a subcommand into an nstar internal processable string
    fn to_command(&self) -> String {
        match self {
            Command::Containers => "containers".to_string(),
            Command::Ls => "ls".to_string(),
            Command::Repositories => "repositories".to_string(),
            Command::Start { name } => {
                if let Some(name) = name {
                    format!("start {}", name)
                } else {
                    "start".to_string()
                }
            }
            Command::Stop { name } => {
                if let Some(name) = name {
                    format!("stop {}", name)
                } else {
                    "stop".to_string()
                }
            }
            Command::Shutdown => "shutdown".to_string(),
        }
    }
}

async fn process<W: std::io::Write>(
    client: &mut Client,
    terminal: &mut W,
    input: &str,
) -> Result<bool> {
    let mut split = input.split_whitespace();
    if let Some(cmd) = split.next() {
        match cmd {
            "exit" | "quit" => return Ok(false),
            "containers" | "ls" => {
                let containers = client.containers().await?;
                pretty::containers(terminal, &containers)?;
            }
            "repositories" => {
                let repositories = client.repositories().await?;
                pretty::repositories(terminal, &repositories)?;
            }
            "start" => {
                let mut containers = client.containers().await?;
                let containers = containers
                    .drain(..)
                    .filter(|c| c.manifest.init.is_some()) // Filter resource containers
                    .filter(|c| c.process.is_none()) // Filter started containers
                    .map(|c| c.manifest.name)
                    .collect::<Vec<_>>();
                if let Some(n) = split.next() {
                    // Exact match
                    if containers.iter().any(|c| c == n) {
                        client.start(n).await?;
                    } else {
                        let re = regex::Regex::new(n)?;
                        for name in containers.iter().filter(|c| re.is_match(&c)) {
                            client.start(&name).await?;
                        }
                    }
                } else {
                    // No argument - stop all running containers
                    for name in &containers {
                        client.start(&name).await?;
                    }
                }
            }
            "stop" => {
                let mut containers = client.containers().await?;
                let containers = containers
                    .drain(..)
                    .filter(|c| c.manifest.init.is_some()) // Filter resource containers
                    .filter(|c| c.process.is_some()) // Filter stopped containers
                    .map(|c| c.manifest.name)
                    .collect::<Vec<_>>();
                if let Some(n) = split.next() {
                    // Exact match
                    if containers.iter().any(|c| c == n) {
                        client.stop(n).await?;
                    } else {
                        let re = regex::Regex::new(n)?;
                        for name in containers.iter().filter(|c| re.is_match(&c)) {
                            client.stop(&name).await?;
                        }
                    }
                } else {
                    // No argument - stop all running containers
                    for name in &containers {
                        client.stop(&name).await?;
                    }
                }
            }
            _ => (),
        }
    }
    Ok(true)
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();

    let (mut terminal, mut input, interactive): (Output, Input, bool) = match opt.cmd {
        Some(cmd) => (
            Box::new(std::io::stdout()) as Output,
            Box::new(once(ready(cmd.to_command()))) as Input,
            false,
        ),
        _ => {
            let (output, input) = terminal::Terminal::new()?;
            (Box::new(output), Box::new(input) as Input, true)
        }
    };

    'outer: loop {
        writeln!(terminal, "Connecting to {}", opt.host)?;

        let mut client = match time::timeout(
            time::Duration::from_secs(2),
            api::client::Client::new(&opt.host),
        )
        .await
        {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                writeln!(terminal, "Failed to connect: {:?}", e)?;
                if interactive {
                    time::sleep(time::Duration::from_secs(1)).await;
                    continue 'outer;
                } else {
                    break;
                }
            }
            Err(_) => {
                if interactive {
                    writeln!(terminal, "Failed to connect: timeout")?;
                    time::sleep(time::Duration::from_secs(1)).await;
                    continue 'outer;
                } else {
                    break;
                }
            }
        };

        writeln!(terminal, "Connected to {}", opt.host)?;

        loop {
            select! {
                notification = client.next() => {
                    if interactive {
                        if let Some(Ok(n)) = notification {
                            pretty::notification(&mut terminal, &n);
                        } else {
                            break;
                        }
                    }
                }
                input = input.next() => {
                    if let Some(input) = input {
                        match process(&mut client, &mut terminal, &input).await {
                            Ok(n) => if !n {
                                break 'outer;
                            }
                            Err(e) => {
                                writeln!(&mut terminal, "Error: {:?}", e)?;
                                break;
                            }

                        }
                    } else {
                        break 'outer;
                    };
                }
            }
        }

        if interactive {
            writeln!(terminal, "Disconnected")?;
            time::sleep(time::Duration::from_secs(1)).await;
        } else {
            break;
        }
    }
    Ok(())
}
