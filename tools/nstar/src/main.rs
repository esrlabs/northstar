//! Northstar console client

#![deny(clippy::all)]
#![deny(missing_docs)]

use anyhow::{anyhow, Context, Error, Result};
use api::{client::Client, model::Message};
use futures::{sink::SinkExt, StreamExt};
use northstar::{
    api::{
        self,
        model::{Container, NonNullString, Request},
    },
    common::version::Version,
};
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    path::PathBuf,
    process,
    str::FromStr,
};
use structopt::{clap, clap::AppSettings, StructOpt};
use tokio::{
    fs,
    io::{copy, AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader},
    net::{TcpStream, UnixStream},
    time,
};

trait N: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> N for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

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
enum Subcommand {
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
        /// Command line arguments
        #[structopt(short, long)]
        args: Option<Vec<String>>,
        /// Environment variables in KEY=VALUE format
        #[structopt(short, long)]
        env: Option<Vec<String>>,
    },
    /// Stop a container
    Kill {
        /// Container name
        name: String,
        /// Container version
        version: Version,
        /// Signal
        signal: Option<i32>,
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
    /// Request container statistics
    ContainerStats {
        /// Container name
        name: String,
        /// Container version
        version: Version,
    },
}

/// CLI
#[derive(StructOpt)]
struct Opt {
    /// Northstar address
    #[structopt(short, long, default_value = DEFAULT_HOST)]
    pub url: url::Url,
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
            Subcommand::Start {
                name,
                version,
                args,
                env,
            } => {
                // Convert args
                let args = if let Some(args) = args {
                    let mut non_null = Vec::with_capacity(args.len());
                    for arg in args {
                        non_null
                            .push(NonNullString::try_from(arg.as_str()).context("Invalid arg")?);
                    }
                    Some(non_null)
                } else {
                    None
                };

                // Convert env
                let env = if let Some(env) = env {
                    let mut non_null = HashMap::with_capacity(env.len());
                    for env in env {
                        let mut split = env.split('=');
                        let key = split
                            .next()
                            .ok_or_else(|| anyhow!("Invalid env"))
                            .and_then(|s| NonNullString::try_from(s).context("Invalid key"))?;
                        let value = split
                            .next()
                            .ok_or_else(|| anyhow!("Invalid env"))
                            .and_then(|s| NonNullString::try_from(s).context("Invalid value"))?;
                        non_null.insert(key, value);
                    }
                    Some(non_null)
                } else {
                    None
                };

                Ok(Request::Start(
                    Container::new(name.try_into()?, version),
                    args,
                    env,
                ))
            }
            Subcommand::Kill {
                name,
                version,
                signal,
            } => Ok(Request::Kill(
                Container::new(name.try_into()?, version),
                signal.unwrap_or(15),
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
            Subcommand::ContainerStats { name, version } => Ok(Request::ContainerStats(
                Container::new(name.try_into()?, version),
            )),
            Subcommand::Notifications { .. } | Subcommand::Completion { .. } => unreachable!(),
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let opt = Opt::from_args();
    let timeout = time::Duration::from_secs(5);

    let io = match opt.url.scheme() {
        "tcp" => {
            let addresses = opt.url.socket_addrs(|| Some(4200))?;
            let address = addresses
                .first()
                .ok_or_else(|| anyhow!("Failed to resolve {}", opt.url))?;
            let stream = time::timeout(timeout, TcpStream::connect(address))
                .await
                .context("Failed to connect")??;

            Box::new(stream) as Box<dyn N>
        }
        "unix" => {
            let stream = time::timeout(timeout, UnixStream::connect(opt.url.path()))
                .await
                .context("Failed to connect")??;
            Box::new(stream) as Box<dyn N>
        }
        _ => return Err(anyhow!("Invalid url")),
    };

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
                let framed = Client::new(io, Some(100), opt.timeout)
                    .await
                    .with_context(|| format!("Failed to connect to {}", opt.url))?
                    .framed();

                let mut lines = BufReader::new(framed).lines();
                for _ in 0..number.unwrap_or(usize::MAX) {
                    match lines.next_line().await.context("Failed to read stream")? {
                        Some(line) => println!("{}", line),
                        None => break,
                    }
                }
            } else {
                let client = Client::new(io, Some(100), opt.timeout)
                    .await
                    .with_context(|| format!("Failed to connect to {}", opt.url))?;
                let mut notifications = client.take(number.unwrap_or(usize::MAX));
                while let Some(notification) = notifications.next().await {
                    let notification = notification.context("Failed to receive notification")?;
                    pretty::notification(&notification);
                }
                process::exit(0);
            }
        }
        // Request response mode
        command => {
            // Connect
            let mut framed = Client::new(io, None, opt.timeout)
                .await
                .context("Failed to connect")?
                .framed();

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
