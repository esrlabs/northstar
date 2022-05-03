//! Northstar console client

#![deny(clippy::all)]
#![deny(missing_docs)]

use anyhow::{anyhow, bail, Context, Result};
use api::{client::Client, model::Message};
use clap::{self, IntoApp, Parser};
use futures::{sink::SinkExt, StreamExt};
use northstar::{
    api::{
        self,
        model::{Container, NonNulString, Request},
    },
    common::{name::Name, version::Version},
};
use std::{collections::HashMap, convert::TryFrom, path::PathBuf, process, str::FromStr};
use tokio::{
    fs,
    io::{copy, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
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
    Box::leak(Box::new(format!("Northstar API version {}", api::VERSION)))
}

/// Subcommands
#[derive(Parser, Clone)]
#[clap(name = "nstar", author, about = about())]
enum Subcommand {
    /// List available containers
    #[clap(alias = "ls", alias = "list")]
    Containers,
    /// List configured repositories
    #[clap(alias = "repos")]
    Repositories,
    /// Mount a container
    Mount {
        /// Container name and optional version
        #[clap(value_name = "name[:version]")]
        containers: Vec<String>,
    },
    /// Umount a container
    Umount {
        /// Container name and optional version
        #[clap(value_name = "name[:version]")]
        containers: Vec<String>,
    },
    /// Start a container
    Start {
        /// Container name and optional version
        #[clap(value_name = "name[:version]")]
        container: String,
        /// Command line arguments
        #[clap(short, long)]
        args: Option<Vec<String>>,
        /// Environment variables in KEY=VALUE format
        #[clap(short, long)]
        env: Option<Vec<String>>,
    },
    /// Stop a container
    Kill {
        /// Container name and optional version
        #[clap(value_name = "name[:version]")]
        container: String,
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
        /// Container name and optional version
        #[clap(value_name = "name[:version]")]
        container: String,
    },
    /// Shutdown Northstar
    Shutdown,
    /// Notifications
    Notifications {
        /// Exit after n notifications
        #[clap(short, long)]
        number: Option<usize>,
    },
    /// Shell completion script generation
    Completion {
        /// Output directory where to generate completions into
        #[clap(short, long)]
        output: Option<PathBuf>,
        /// Generate completions for shell type
        #[clap(short, long)]
        shell: clap_complete::Shell,
    },
    /// Display information about the container
    Container {
        /// Container name and optional version
        #[clap(value_name = "name[:version]")]
        container: String,
    },
    /// Create a token
    Token {
        /// Token target
        target: String,
        /// Shared info
        shared: String,
    },
    /// Create a token
    VerifyToken {
        /// Token
        token: String,
        /// User
        user: String,
        /// Shared info
        shared: String,
    },
    /// Identification
    Ident,
}

/// CLI
#[derive(Parser)]
struct Opt {
    /// Northstar address
    #[clap(short, long, default_value = DEFAULT_HOST)]
    pub url: url::Url,
    /// Output json
    #[clap(short, long)]
    pub json: bool,
    /// Connect timeout in seconds
    #[clap(short, long, default_value = "10", parse(try_from_str = parse_secs))]
    pub timeout: time::Duration,
    /// Command
    #[clap(subcommand)]
    pub command: Subcommand,
}

/// Parse a str containing a u64 into a `std::time::Duration` and take the value
/// as seconds
fn parse_secs(src: &str) -> Result<time::Duration, anyhow::Error> {
    u64::from_str(src)
        .map(time::Duration::from_secs)
        .map_err(Into::into)
}

/// Parse the container name and version out of the user input
///
/// # Format
///
/// The string format for the container name is specified as `<name>[:<version>]`.
///
/// if the version is not specified, Northstar is queried for all the versions associated to
/// `<name>` and only if a single version is found, it is used.
///
async fn parse_container<T>(name: &str, client: &mut Client<T>) -> Result<Container>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (name, version): (Name, Version) = if let Some((name, version)) = name.split_once(':') {
        (Name::try_from(name)?, Version::parse(version)?)
    } else {
        let name = Name::try_from(name)?;
        let versions: Vec<Version> = client
            .containers()
            .await?
            .into_iter()
            .filter_map(|c| (c.manifest.name == name).then(|| c.manifest.version))
            .collect();

        if versions.is_empty() {
            bail!("no container found with name {}", name);
        } else if versions.len() > 1 {
            bail!("container {} has multiple versions: {:?}", name, versions);
        } else {
            (name, versions[0].clone())
        }
    };
    Ok(Container::new(name, version))
}

async fn command_to_request<T: AsyncRead + AsyncWrite + Unpin>(
    command: Subcommand,
    client: &mut Client<T>,
) -> Result<Request> {
    match command {
        Subcommand::Ident => Ok(Request::Ident),
        Subcommand::Containers => Ok(Request::Containers),
        Subcommand::Repositories => Ok(Request::Repositories),
        Subcommand::Mount { containers } => {
            let mut converted = Vec::with_capacity(containers.len());
            for container in containers {
                converted.push(parse_container(&container, client).await?);
            }
            Ok(Request::Mount(converted))
        }
        Subcommand::Umount { containers } => {
            let mut converted = Vec::with_capacity(containers.len());
            for container in containers {
                converted.push(parse_container(&container, client).await?);
            }
            Ok(Request::Umount(converted))
        }
        Subcommand::Start {
            container,
            args,
            env,
        } => {
            let container = parse_container(&container, client).await?;

            // Convert args
            let args: Result<Vec<_>, _> = args
                .unwrap_or_default()
                .into_iter()
                .map(NonNulString::try_from)
                .collect();

            // Convert env
            let env: Result<HashMap<_, _>, _> = env
                .unwrap_or_default()
                .into_iter()
                .map(|env| {
                    env.split_once('=')
                        .ok_or_else(|| anyhow!("invalid env"))
                        .and_then(|(k, v)| {
                            match (NonNulString::try_from(k), NonNulString::try_from(v)) {
                                (Ok(k), Ok(v)) => Ok((k, v)),
                                (Err(_), _) => Err(anyhow!("invalid key")),
                                (_, Err(_)) => Err(anyhow!("invalid value")),
                            }
                        })
                })
                .collect();

            Ok(Request::Start(container, args?, env?))
        }
        Subcommand::Kill { container, signal } => {
            let container = parse_container(&container, client).await?;
            let signal = signal.unwrap_or(15);
            Ok(Request::Kill(container, signal))
        }
        Subcommand::Install { npk, repository } => {
            let size = npk.metadata().map(|m| m.len())?;
            Ok(Request::Install(repository, size))
        }
        Subcommand::Uninstall { container } => Ok(Request::Uninstall(
            parse_container(&container, client).await?,
        )),
        Subcommand::Shutdown => Ok(Request::Shutdown),
        Subcommand::Container { container } => {
            let container = parse_container(&container, client).await?;
            Ok(Request::Container(container))
        }
        Subcommand::Token { target, shared } => {
            let target = target.as_bytes().to_vec();
            let shared = shared.as_bytes().to_vec();
            Ok(Request::TokenCreate(target, shared))
        }
        Subcommand::VerifyToken {
            token,
            user,
            shared,
        } => {
            let user = user.as_bytes().to_vec();
            let shared = shared.as_bytes().to_vec();
            let token = hex::decode(token.as_bytes()).context("invalid token")?;
            let token: [u8; 40] = token.try_into().map_err(|_| anyhow!("invalid token"))?;
            Ok(Request::TokenVerify(token.into(), user, shared))
        }
        Subcommand::Notifications { .. } | Subcommand::Completion { .. } => unreachable!(),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    let timeout = time::Duration::from_secs(5);

    // Generate shell completions and exit on give subcommand
    if let Subcommand::Completion { output, shell } = opt.command {
        let mut output: Box<dyn std::io::Write> = match output {
            Some(path) => {
                println!("Generating {} completions to {}", shell, path.display());
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(&path)
                    .with_context(|| format!("failed to open {}", path.display()))?;
                Box::new(file)
            }
            None => Box::new(std::io::stdout()),
        };

        clap_complete::generate(
            shell,
            &mut Opt::command(),
            Opt::command().get_name().to_string(),
            &mut output,
        );

        process::exit(0);
    }

    let io = match opt.url.scheme() {
        "tcp" => {
            let addresses = opt.url.socket_addrs(|| Some(4200))?;
            let address = addresses
                .first()
                .ok_or_else(|| anyhow!("failed to resolve {}", opt.url))?;
            let stream = time::timeout(timeout, TcpStream::connect(address))
                .await
                .context("failed to connect")??;

            Box::new(stream) as Box<dyn N>
        }
        "unix" => {
            let stream = time::timeout(timeout, UnixStream::connect(opt.url.path()))
                .await
                .context("failed to connect")??;
            Box::new(stream) as Box<dyn N>
        }
        _ => return Err(anyhow!("invalid url")),
    };

    match opt.command {
        // Subscribe to notifications and print them
        Subcommand::Notifications { number } => {
            if opt.json {
                let mut framed = Client::new(io, Some(100), opt.timeout)
                    .await
                    .with_context(|| format!("failed to connect to {}", opt.url))?
                    .framed();

                let mut lines = BufReader::new(framed.get_mut()).lines();
                for _ in 0..number.unwrap_or(usize::MAX) {
                    match lines.next_line().await.context("failed to read stream")? {
                        Some(line) => println!("{}", line),
                        None => break,
                    }
                }
            } else {
                let client = Client::new(io, Some(100), opt.timeout)
                    .await
                    .with_context(|| format!("failed to connect to {}", opt.url))?;
                let mut notifications = client.take(number.unwrap_or(usize::MAX));
                while let Some(notification) = notifications.next().await {
                    let notification = notification.context("failed to receive notification")?;
                    pretty::notification(&notification);
                }
                process::exit(0);
            }
        }
        // Request response mode
        command => {
            // Connect
            let mut client = Client::new(io, None, opt.timeout)
                .await
                .context("failed to connect")?;

            // Convert the subcommand into a request
            let request = command_to_request(command.clone(), &mut client)
                .await
                .context("failed to convert command into request")?;

            // If the raw json mode is requested nstar needs to operate on the raw stream instead
            // of `Client<T>`
            let mut framed = client.framed();

            framed
                .send(Message::Request { request })
                .await
                .context("failed to send request")?;

            // Extra file transfer for install hack
            if let Subcommand::Install { npk, .. } = command {
                framed.flush().await.context("failed to flush")?;
                framed.get_mut().flush().await.context("failed to flush")?;

                copy(
                    &mut fs::File::open(npk).await.context("failed to open npk")?,
                    &mut framed.get_mut(),
                )
                .await
                .context("failed to stream npk")?;
            }

            framed.get_mut().flush().await.context("failed to flush")?;

            if opt.json {
                let response = BufReader::new(framed.get_mut())
                    .lines()
                    .next_line()
                    .await
                    .context("failed to receive response")?
                    .ok_or_else(|| anyhow!("failed to receive response"))?;
                println!("{}", response);
                process::exit(0);
            } else {
                // Read next deserialized response and pretty print
                let exit = match framed
                    .next()
                    .await
                    .ok_or_else(|| anyhow!("failed to receive response"))??
                {
                    api::model::Message::Response { response } => pretty::response(&response),
                    _ => unreachable!(),
                };
                process::exit(exit);
            }
        }
    };

    Ok(())
}
