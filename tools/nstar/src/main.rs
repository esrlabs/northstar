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

use anyhow::{anyhow, Context, Error, Result};
use api::{client::Client, model::Message};
use futures::{sink::SinkExt, StreamExt};
use northstar::api::{
    self,
    model::{Container, Request, Version},
};
use std::{
    convert::{TryFrom, TryInto},
    path::PathBuf,
    process,
    str::FromStr,
    time,
};
use structopt::{clap, clap::AppSettings, StructOpt};
use tokio::{
    fs,
    io::{copy, AsyncBufReadExt, BufReader},
};

mod pretty;

/// Default nstar address
const DEFAULT_HOST: &str = "tcp://localhost:4200";

/// About string for CLI
fn about() -> &'static str {
    Box::leak(Box::new(format!(
        "Northstar API version {}",
        api::model::version()
    )))
}

/// Subcommands
#[derive(StructOpt, Clone)]
#[structopt(name = "nstar", author, about = about(), global_setting(AppSettings::ColoredHelp))]
pub enum Subcommand {
    /// List available containers
    #[structopt(alias = "ls", alias = "list")]
    Containers,
    /// List configured repositories
    #[structopt(alias = "repos")]
    Repositories,
    /// Mount a container
    Mount {
        /// Container name
        name: String,
        /// Container version
        version: Version,
    },
    /// Umount a container
    Umount {
        /// Container name
        name: String,
        /// Container version
        version: Version,
    },
    /// Start a container
    Start {
        /// Container name
        name: String,
        /// Container version
        version: Version,
    },
    /// Stop a container
    Stop {
        /// Container name
        name: String,
        /// Container version
        version: Version,
        /// Timeout
        #[structopt(default_value = "5")]
        timeout: u64,
    },
    /// Install a npk
    Install {
        /// Path to the .npk file
        npk: PathBuf,
        /// Target repository
        repository: String,
    },
    /// Uninstall a container
    Uninstall {
        /// Container name
        name: String,
        /// Container version
        version: Version,
    },
    /// Shutdown Northstar
    Shutdown,
    /// Notifications
    Notifications {
        /// Exit after n notifications
        #[structopt(short, long)]
        number: Option<usize>,
    },
    /// Shell completion script generation
    Completion {
        /// Output directory where to generate completions into
        #[structopt(short, long)]
        output: PathBuf,
        /// Generate completions for shell type
        #[structopt(short, long)]
        shell: clap::Shell,
    },
}

/// CLI
#[derive(StructOpt)]
pub struct Opt {
    /// Northstar address
    #[structopt(short, long, default_value = DEFAULT_HOST)]
    pub host: url::Url,
    /// Output json
    #[structopt(short, long)]
    pub json: bool,
    /// Connect timeout in seconds
    #[structopt(short, long, default_value = "10", parse(try_from_str = parse_secs))]
    pub timeout: time::Duration,
    /// Command
    #[structopt(subcommand)]
    pub command: Subcommand,
}

/// Parse a str containing a u64 into a `std::time::Duration` and take the value
/// as seconds
fn parse_secs(src: &str) -> Result<time::Duration, anyhow::Error> {
    u64::from_str(src)
        .map(time::Duration::from_secs)
        .map_err(Into::into)
}

impl TryFrom<Subcommand> for Request {
    type Error = Error;

    fn try_from(command: Subcommand) -> Result<Self, Self::Error> {
        match command {
            Subcommand::Containers => Ok(Request::Containers),
            Subcommand::Repositories => Ok(Request::Repositories),
            Subcommand::Mount { name, version } => Ok(Request::Mount(vec![Container::new(
                name.try_into()?,
                version,
            )])),
            Subcommand::Umount { name, version } => {
                Ok(Request::Umount(Container::new(name.try_into()?, version)))
            }
            Subcommand::Start { name, version } => {
                Ok(Request::Start(Container::new(name.try_into()?, version)))
            }
            Subcommand::Stop {
                name,
                version,
                timeout,
            } => Ok(Request::Stop(
                Container::new(name.try_into()?, version),
                timeout,
            )),
            Subcommand::Install {
                npk,
                repository: repo_id,
            } => {
                let size = npk.metadata().map(|m| m.len())?;
                Ok(Request::Install(repo_id, size))
            }
            Subcommand::Uninstall { name, version } => Ok(Request::Uninstall(Container::new(
                name.try_into()?,
                version,
            ))),
            Subcommand::Shutdown => Ok(Request::Shutdown),
            Subcommand::Notifications { .. } | Subcommand::Completion { .. } => unreachable!(),
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let opt = Opt::from_args();
    let host = opt.host.clone();
    match opt.command {
        // Generate shell completions and exit on give subcommand
        Subcommand::Completion { output, shell } => {
            println!("Generating {} completions to {}", shell, output.display());
            Opt::clap().gen_completions(env!("CARGO_PKG_NAME"), shell, output);
            process::exit(0);
        }
        // Subscribe to notifications and print them
        Subcommand::Notifications { number } => {
            if opt.json {
                let framed = Client::connect(&host, Some(100), opt.timeout)
                    .await
                    .with_context(|| format!("Failed to connect to {}", opt.host))?;

                let mut lines = BufReader::new(framed).lines();
                for _ in 0..number.unwrap_or(usize::MAX) {
                    match lines.next_line().await.context("Failed to read stream")? {
                        Some(line) => println!("{}", line),
                        None => break,
                    }
                }
            } else {
                let client = Client::new(&opt.host, Some(100), opt.timeout)
                    .await
                    .with_context(|| format!("Failed to connect to {}", opt.host))?;
                let mut notifications = client.take(number.unwrap_or(usize::MAX));
                while let Some(notification) = notifications.next().await {
                    let notification = notification.context("Failed to receive notificaiton")?;
                    pretty::notification(&notification);
                }
                process::exit(0);
            }
        }
        // Request response mode
        command => {
            // Connect
            let mut framed = Client::connect(&host, None, opt.timeout)
                .await
                .with_context(|| format!("Failed to connect to {}", &host))?;

            // Request
            let request = Request::try_from(command.clone())
                .context("Failed to convert command into request")?;
            framed
                .send(Message::new_request(request))
                .await
                .context("Failed to send request")?;

            // Extra file transfer for install hack
            if let Subcommand::Install { npk, .. } = command {
                copy(
                    &mut fs::File::open(npk).await.context("Failed to open npk")?,
                    &mut framed,
                )
                .await
                .context("Failed to stream npk")?;
            }

            if opt.json {
                let response = BufReader::new(framed)
                    .lines()
                    .next_line()
                    .await
                    .context("Failed to receive response")?
                    .ok_or_else(|| anyhow!("Failed to receive response"))?;
                println!("{}", response);
                process::exit(0);
            } else {
                // Read next deserialized response and pretty print
                let exit = match framed
                    .next()
                    .await
                    .ok_or_else(|| anyhow!("Failed to receive response"))??
                {
                    api::model::Message::Response(response) => pretty::response(&response),
                    _ => unreachable!(),
                };
                process::exit(exit);
            }
        }
    };

    Ok(())
}
