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
use npk::manifest::Version;
use std::{
    fmt::Debug,
    io::Write,
    path::{Path, PathBuf},
};
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
    /// Try to stop a container with name `name`
    Install { npk: PathBuf, repository: String },
    /// Try to stop a container with name `name`
    Uninstall { name: String, version: Version },
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
            Command::Install { npk, repository } => {
                format!("install {} {}", npk.display(), repository)
            }
            Command::Uninstall { name, version } => format!("uninstall {} {}", name, version),
        }
    }
}

async fn process<W: std::io::Write>(
    client: &mut Client,
    output: &mut W,
    input: &str,
) -> Result<Option<String>> {
    let mut split = input.split_whitespace();
    if let Some(cmd) = split.next() {
        match cmd {
            "containers" | "ls" => {
                let containers = client.containers().await?;
                pretty::containers(output, &containers)?;
            }
            "repositories" => {
                let repositories = client.repositories().await?;
                pretty::repositories(output, &repositories)?;
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
            "install" => {
                let npk = if let Some(npk) = split.next() {
                    Path::new(npk)
                } else {
                    return Ok(Some("Invalid npk".into()));
                };
                if !npk.exists() {
                    return Ok(Some("No such file or directory".into()));
                }

                let repository = if let Some(repository) = split.next() {
                    repository
                } else {
                    return Ok(Some("Missing repository argument".into()));
                };

                client.install(npk, repository).await?;
            }
            "uninstall" => {
                let name = if let Some(name) = split.next() {
                    name
                } else {
                    return Ok(Some("Missing container name".into()));
                };
                let version = if let Some(version) = split.next() {
                    match Version::parse(version) {
                        Ok(version) => version,
                        Err(e) => return Ok(Some(format!("Invalid version: {}", e))),
                    }
                } else {
                    return Ok(Some("Missing version".into()));
                };
                client.uninstall(name, &version).await?;
            }
            c => return Ok(Some(format!("Unimplemented command \"{}\"", c))),
        }
    }
    Ok(None)
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
                    match input.as_deref() {
                        Some("quit") | Some("exit") => break 'outer,
                        Some(ref input) => {
                            match process(&mut client, &mut terminal, &input).await {
                                Ok(Some(msg)) => writeln!(&mut terminal, "⚠ {}", msg)?,
                                Ok(None) => writeln!(&mut terminal, "✓ {}", input)?,
                                Err(e) => {
                                    writeln!(&mut terminal, "⚠ {:?}", e)?;
                                    break;
                                }

                            }
                        }
                        None => break 'outer,
                    }
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
