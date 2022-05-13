//! Northstar console client

#![deny(clippy::all)]
#![deny(missing_docs)]

use anyhow::{anyhow, bail, Context, Result};
use api::client::Client;
use clap::{self, IntoApp, Parser};
use futures::{future::Either, StreamExt};
use northstar::{
    api::{
        self,
        model::{Container, Token},
    },
    common::name::Name,
};
use std::{collections::HashMap, convert::TryFrom, path::PathBuf, process};
use tokio::{
    io::{AsyncRead, AsyncWrite},
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
#[derive(Parser, Clone, PartialEq)]
#[clap(name = "nstar", author, about = about())]
enum Subcommand {
    /// List available containers
    #[clap(alias = "ls")]
    List,
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
    Inspect {
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
        target: String,
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
    /// Connect timeout in seconds
    #[clap(short, long, default_value = "10s", parse(try_from_str = humantime::parse_duration))]
    pub timeout: time::Duration,
    /// Command
    #[clap(subcommand)]
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
    let container = if let Some((name, _)) = name.split_once(':') {
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

    let notifications = if let Subcommand::Notifications { .. } = opt.command {
        Some(100)
    } else {
        None
    };
    let mut client = Client::new(io, notifications, opt.timeout).await?;

    match opt.command {
        Subcommand::Ident => {
            println!("{}", client.ident().await?);
        }
        Subcommand::List => {
            let mut containers = HashMap::new();
            for container in client.list().await? {
                let inspect = Client::inspect(&mut client, &container).await?;
                containers.insert(container, inspect);
            }
            pretty::list(&containers);
        }
        Subcommand::Repositories => {
            let repositories = client.repositories().await?;
            pretty::repositories(&repositories);
        }
        Subcommand::Mount { containers } => {
            let mut converted = Vec::with_capacity(containers.len());
            for container in containers {
                converted.push(resolve_container(&container, &mut client).await?);
            }
            let result = client.mount_all(&converted).await?;
            pretty::mounts(&result);
        }
        Subcommand::Umount { containers } => {
            let mut converted = Vec::with_capacity(containers.len());
            for container in containers {
                converted.push(resolve_container(&container, &mut client).await?);
            }
            let result = client.umount_all(&converted).await?;
            pretty::umounts(&result);
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
                .collect::<Vec<_>>();
            client.start_with_args_env(&container, args, env).await?;
            println!("started {}", container);
        }
        Subcommand::Kill { container, signal } => {
            let container = resolve_container(&container, &mut client).await?;
            let signal = signal.unwrap_or(15);
            client.kill(&container, signal).await?;
            println!("signalled {} with signal {}", container, signal);
        }
        Subcommand::Install { npk, repository } => {
            client.install(&npk, &repository).await?;
            println!("installed {} into {}", npk.display(), repository);
        }
        Subcommand::Uninstall { container } => {
            let container = resolve_container(&container, &mut client).await?;
            client.uninstall(&container).await?;
            println!("uninstalled {}", container);
        }
        Subcommand::Shutdown => {
            client.shutdown().await;
            println!("shutdown");
        }
        Subcommand::Inspect { container } => {
            let container = resolve_container(&container, &mut client).await?;
            let inspect = Client::inspect(&mut client, &container).await?;
            println!("{}", serde_json::to_string_pretty(&inspect)?);
        }
        Subcommand::Token { target, shared } => {
            let target = target.as_bytes().to_vec();
            let shared = shared.as_bytes().to_vec();
            let token = client.create_token(&target, &shared).await?;
            println!("created {}", hex::encode(token))
        }
        Subcommand::VerifyToken {
            token,
            target,
            shared,
        } => {
            let target = target.as_bytes().to_vec();
            let shared = shared.as_bytes().to_vec();
            let token = hex::decode(token.as_bytes()).context("invalid token")?;
            let token: [u8; 40] = token.try_into().map_err(|_| anyhow!("invalid token"))?;
            let token: Token = token.into();
            let result = client.verify_token(&token, &target, shared).await?;
            println!("{:?}", result);
        }
        Subcommand::Notifications { number } => {
            let mut stream = match number {
                Some(number) => Either::Left(client.take(number)),
                None => Either::Right(client),
            };
            while let Some(notification) = stream.next().await {
                let notification = notification?;
                pretty::notification(&notification);
            }
        }
        Subcommand::Completion { .. } => unreachable!(),
    }

    Ok(())
}
