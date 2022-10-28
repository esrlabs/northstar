//! Northstar console client

#![deny(clippy::all)]
#![deny(missing_docs)]

use anyhow::{anyhow, bail, Context, Result};
use clap::{self, Parser};
use futures::StreamExt;
use northstar_client::{
    model::{Container, Token},
    Client, Name, VERSION,
};
use std::{collections::HashMap, convert::TryFrom, path::PathBuf, process};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, UnixStream},
    time,
};
use tokio_util::either::Either;
use trace::Trace;

mod completion;
mod pretty;
mod seccomp;
mod trace;

/// Default nstar address
const DEFAULT_HOST: &str = "tcp://localhost:4200";

/// About string for CLI
fn about() -> &'static str {
    Box::leak(Box::new(format!("Northstar API version {}", VERSION)))
}

/// Subcommands
#[derive(Parser, Clone, PartialEq)]
enum Subcommand {
    /// List available containers
    #[command(alias = "ls")]
    List,
    /// List configured repositories
    #[command(alias = "repos")]
    Repositories,
    /// Mount a container
    Mount {
        /// Container name and optional version
        #[arg(value_name = "name[:version]")]
        containers: Vec<String>,
    },
    /// Umount a container
    Umount {
        /// Container name and optional version
        #[arg(value_name = "name[:version]")]
        containers: Vec<String>,
    },
    /// Start a container
    Start {
        /// Container name and optional version
        #[arg(value_name = "name[:version]")]
        container: String,
        /// Command line arguments
        #[arg(short, long)]
        args: Option<Vec<String>>,
        /// Environment variables in KEY=VALUE format
        #[arg(short, long)]
        env: Option<Vec<String>>,
    },
    /// Stop a container
    Kill {
        /// Container name and optional version
        #[arg(value_name = "name[:version]")]
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
        /// Wipe containers persistent dir (if present)
        #[arg(short, long)]
        wipe: bool,
        /// Container name and optional version
        #[arg(value_name = "name[:version]")]
        container: String,
    },
    /// Shutdown Northstar
    Shutdown,
    /// Notifications
    Notifications {
        /// Exit after n notifications
        #[arg(short, long)]
        number: Option<usize>,
    },
    /// Shell completion script generation
    Completion {
        /// Output file where to generate completions into.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Generate completions for shell type
        #[arg(short, long)]
        shell: clap_complete::Shell,
    },
    /// Display information about the container
    Inspect {
        /// Container name and optional version
        #[arg(value_name = "name[:version]")]
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
    /// Generate seccomp profile from strace
    Seccomp {
        /// Path to strace log file
        input: PathBuf,
        /// Whether or not to allow the syscalls defined by the default profile
        #[arg(long)]
        no_default_profile: bool,
    },
}

/// Northstar console client
#[derive(Parser)]
#[command(author, version, about = about(), long_about = None)]
struct Opt {
    /// Northstar address
    #[arg(short, long, default_value = DEFAULT_HOST)]
    pub url: url::Url,
    /// Output raw json payload
    #[arg(short, long)]
    pub json: bool,
    /// Connect timeout in seconds
    #[arg(short, long, default_value = "10s", value_parser = humantime::parse_duration)]
    pub timeout: time::Duration,
    /// Command
    #[command(subcommand)]
    pub command: Subcommand,
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
async fn resolve_container<T>(name: &str, client: &mut Client<T>) -> Result<Container>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let container = if name.contains(':') {
        Container::try_from(name)?
    } else {
        let name = Name::try_from(name)?;
        let mut matches = client
            .list()
            .await?
            .into_iter()
            .filter(|c| (c.name() == &name));

        if let Some(r#match) = matches.next() {
            if matches.next().is_some() {
                bail!("container {} has multiple versions", name);
            } else {
                r#match
            }
        } else {
            bail!("no container found with name {}", name);
        }
    };
    Ok(container)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    let timeout = time::Duration::from_secs(5);

    // Generate shell completions and exit on give subcommand
    match opt.command {
        Subcommand::Completion { output, shell } => {
            completion::completion(output, shell)?;
            process::exit(0);
        }
        Subcommand::Seccomp {
            input,
            no_default_profile,
        } => {
            seccomp::seccomp(input, no_default_profile)?;
            process::exit(0);
        }
        _ => (),
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

            Either::Left(stream)
        }
        "unix" => {
            let stream = time::timeout(timeout, UnixStream::connect(opt.url.path()))
                .await
                .context("failed to connect")??;
            Either::Right(stream)
        }
        _ => return Err(anyhow!("invalid url")),
    };

    let notifications = if let Subcommand::Notifications { .. } = &opt.command {
        Some(100)
    } else {
        None
    };

    // Wrap the io in a tracing struct if the json option is set on the cli
    let io = if opt.json {
        Either::Left(Trace::new(io, std::io::stdout()))
    } else {
        Either::Right(io)
    };

    let mut client = Client::new(io, notifications, opt.timeout).await?;

    match opt.command {
        Subcommand::Ident => {
            println!("{}", client.ident().await?);
        }
        Subcommand::List => {
            let mut containers = HashMap::new();
            for container in client.list().await? {
                let inspect = Client::inspect(&mut client, container.clone()).await?;
                containers.insert(container, inspect);
            }
            if !opt.json {
                pretty::list(&containers);
            }
        }
        Subcommand::Repositories => {
            let repositories = client.repositories().await?;
            if !opt.json {
                pretty::repositories(&repositories);
            }
        }
        Subcommand::Mount { containers } => {
            let mut converted = Vec::with_capacity(containers.len());
            for container in containers {
                converted.push(resolve_container(&container, &mut client).await?.clone());
            }
            let result = client.mount_all(converted).await?;
            if !opt.json {
                pretty::mounts(&result);
            }
        }
        Subcommand::Umount { containers } => {
            let mut converted = Vec::with_capacity(containers.len());
            for container in containers {
                converted.push(resolve_container(&container, &mut client).await?.clone());
            }
            let result = client.umount_all(converted).await?;
            if !opt.json {
                pretty::umounts(&result);
            }
        }
        Subcommand::Start {
            container,
            args,
            env,
        } => {
            let container = resolve_container(&container, &mut client).await?;
            let args = args.unwrap_or_default();
            let env = env.unwrap_or_default();
            let env = env
                .iter()
                .map(|s| s.split_once('=').expect("invalid env. use key=value"))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<Vec<_>>();
            client
                .start_with_args_env(container.clone(), args, env)
                .await?;
            if !opt.json {
                println!("started {}", container);
            }
        }
        Subcommand::Kill { container, signal } => {
            let container = resolve_container(&container, &mut client).await?;
            let signal = signal.unwrap_or(15);
            client.kill(container.clone(), signal).await?;
            if !opt.json {
                println!("signalled {} with signal {}", container, signal);
            }
        }
        Subcommand::Install { npk, repository } => {
            client.install_file(&npk, &repository).await?;
            if !opt.json {
                println!("installed {} into {}", npk.display(), repository);
            }
        }
        Subcommand::Uninstall { container, wipe } => {
            let container = resolve_container(&container, &mut client).await?;
            client.uninstall(container.clone(), wipe).await?;
            if !opt.json {
                println!("uninstalled {}", container);
            }
        }
        Subcommand::Shutdown => {
            client.shutdown().await;
            if !opt.json {
                println!("shutdown");
            }
        }
        Subcommand::Inspect { container } => {
            let container = resolve_container(&container, &mut client).await?;
            let inspect = Client::inspect(&mut client, container).await?;
            if !opt.json {
                println!("{}", serde_json::to_string_pretty(&inspect)?);
            }
        }
        Subcommand::Token { target, shared } => {
            let target = Name::try_from(target)?;
            let shared = shared.as_bytes().to_vec();
            let token = client.create_token(target, &shared).await?;
            if !opt.json {
                println!("created token {}", base64::encode(token))
            }
        }
        Subcommand::VerifyToken {
            token,
            user,
            shared,
        } => {
            let user = Name::try_from(user)?;
            let shared = shared.as_bytes().to_vec();
            let token = base64::decode(token.as_bytes()).context("invalid token")?;
            let token: Token = token.into();
            let result = client.verify_token(&token, user, shared).await?;
            if !opt.json {
                println!("{:?}", result);
            }
        }
        Subcommand::Notifications { number } => {
            let mut stream = match number {
                Some(number) => Either::Left(client.take(number)),
                None => Either::Right(client),
            };
            while let Some(notification) = stream.next().await {
                let notification = notification?;
                if !opt.json {
                    pretty::notification(&notification);
                }
            }
        }
        _ => unreachable!(),
    }

    Ok(())
}
