use anyhow::{anyhow, Context, Result};
use clap::Parser;
use futures::{
    future::{pending, ready, try_join_all},
    stream::repeat,
    FutureExt, StreamExt,
};
use rand::{distributions::Standard, prelude::Distribution, seq::IteratorRandom};

use humantime::{format_duration, parse_duration};
use log::{debug, info};
use northstar_client::{
    model::{self, Container, ContainerData},
    Client,
};
use rand::{thread_rng, Rng};
use std::{path::PathBuf, str::FromStr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, UnixStream},
    pin, select,
    sync::Barrier,
    task::{self, yield_now},
    time::{self},
};
use tokio_stream::wrappers::IntervalStream;
use tokio_util::{either::Either, sync::CancellationToken};
use url::Url;

#[derive(Clone, Debug, PartialEq)]
enum Mode {
    Monkey,
    MountUmount,
    StartStop,
    StartStopUmount,
    MountStartStopUmount,
    InstallUninstall,
}

impl FromStr for Mode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "monkey" => Ok(Mode::Monkey),
            "mount-umount" => Ok(Mode::MountUmount),
            "start-stop" => Ok(Mode::StartStop),
            "start-stop-umount" => Ok(Mode::StartStopUmount),
            "mount-start-stop-umount" => Ok(Mode::StartStopUmount),
            "install-uninstall" => Ok(Mode::InstallUninstall),
            _ => Err("invalid mode"),
        }
    }
}

enum MonkeyAction {
    Start,
    Kill(i32),
    Mount,
    Umount,
}

impl Distribution<MonkeyAction> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> MonkeyAction {
        match rng.gen_range(0..4) {
            0 => MonkeyAction::Start,
            1 => MonkeyAction::Kill(rng.gen_range(1..=15)),
            2 => MonkeyAction::Mount,
            _ => MonkeyAction::Umount,
        }
    }
}

/// Northstar stress test utility
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Opt {
    /// Runtime address
    #[clap(short, long, default_value = "tcp://localhost:4200")]
    url: url::Url,

    /// Duration to run the test for in seconds
    #[clap(short, long, parse(try_from_str = parse_duration))]
    duration: Option<Duration>,

    /// Random delay between each iteration e.g 1s
    #[clap(short, long, parse(try_from_str = parse_duration))]
    random_delay: Option<Duration>,

    /// Mode
    #[clap(short, long, default_value = "start-stop")]
    mode: Mode,

    /// Npk for install-uninstall mode
    #[clap(long, required_if_eq("mode", "install-uninstall"))]
    npk: Option<PathBuf>,

    /// Repository for install-uninstall mode
    #[clap(long, required_if_eq("mode", "install-uninstall"))]
    repository: Option<String>,

    /// Initial random delay in ms to randomize tasks
    #[clap(short, long, parse(try_from_str = parse_duration), default_value = "1s")]
    initial_random_delay: Duration,
}

pub trait N: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> N for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

async fn io(url: &Url) -> Result<Box<dyn N + Sync>> {
    let timeout = time::Duration::from_secs(5);
    match url.scheme() {
        "tcp" => {
            let addresses = url.socket_addrs(|| Some(4200))?;
            let address = addresses
                .first()
                .ok_or_else(|| anyhow!("failed to resolve {}", url))?;
            let stream = time::timeout(timeout, TcpStream::connect(address))
                .await
                .context("failed to connect")??;

            Ok(Box::new(stream) as Box<dyn N + Sync>)
        }
        "unix" => {
            let stream = time::timeout(timeout, UnixStream::connect(url.path()))
                .await
                .context("failed to connect")??;
            Ok(Box::new(stream) as Box<dyn N + Sync>)
        }
        _ => Err(anyhow!("invalid url")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::parse();

    info!("mode: {:?}", opt.mode);
    info!("duration: {:?}", opt.duration);
    debug!("address: {}", opt.url.to_string());
    debug!("repository: {:?}", opt.repository);
    debug!("npk: {:?}", opt.npk);
    debug!("random: {:?}", opt.random_delay);

    match opt.mode {
        Mode::Monkey => monkey(&opt).await,
        Mode::MountUmount
        | Mode::StartStop
        | Mode::StartStopUmount
        | Mode::MountStartStopUmount => start_stop(&opt).await,
        Mode::InstallUninstall => install_uninstall(&opt).await,
    }
}

async fn start_stop(opt: &Opt) -> Result<()> {
    // Get a list of installed applications
    debug!("Getting list of startable containers");
    let mut client = Client::new(io(&opt.url).await?, None, time::Duration::from_secs(30)).await?;
    let mut containers: Vec<Container> = Vec::new();
    for container in client.list().await? {
        let data = Client::inspect(&mut client, &container).await?;
        if data.manifest.init.is_some() {
            containers.push(container);
        }
    }
    drop(client);

    let mut tasks = Vec::with_capacity(containers.len());
    let stop = CancellationToken::new();

    // Sync the start of all tasks
    let start_barrier = Arc::new(Barrier::new(containers.len()));
    let mut rng = thread_rng();

    for container in containers {
        let mode = opt.mode.clone();
        let random = opt.random_delay;
        let start_barrier = start_barrier.clone();
        let stop = stop.clone();
        let url = opt.url.clone();
        let initial_delay = time::Duration::from_millis(
            rng.gen_range(1..opt.initial_random_delay.as_millis()) as u64,
        );

        debug!("Spawning task for {}", container);
        let task = task::spawn(async move {
            let mut client =
                Client::new(io(&url).await?, None, time::Duration::from_secs(10)).await?;
            start_barrier.wait().await;

            info!(
                "Delaying task start of {} for {}",
                container,
                format_duration(initial_delay)
            );
            time::sleep(initial_delay).await;

            for iteration in 0u64.. {
                let mode = &mode;
                let container = &container;

                if *mode == Mode::MountStartStopUmount || *mode == Mode::MountUmount {
                    info!("{} mount", &container);
                    client.mount(container).await?;
                    info!("{}: awaiting mount", container);
                    await_container_state(&mut client, container, |state| state.mounted).await?;
                    info!("{}: mounted", container);
                }

                if *mode != Mode::MountUmount {
                    info!("{}: start", container);
                    client.start(container).await?;
                    info!("{}: awaiting start", container);
                    await_container_state(&mut client, container, |state| state.process.is_some())
                        .await?;
                    info!("{}: started", container);
                }

                if let Some(delay) = random {
                    info!("{}: sleeping for {:?}", container, delay);
                    time::sleep(delay).await;
                }

                if *mode != Mode::MountUmount {
                    info!("{}: killing", container);
                    client
                        .kill(container.clone(), 15)
                        .await
                        .context("failed to stop container")?;

                    info!("{}: awaiting exit", container);
                    await_container_state(&mut client, container, |state| state.process.is_none())
                        .await?;
                    info!("{}: exited", container);
                }

                // Check if we need to umount
                if *mode != Mode::StartStop {
                    info!("{}: umounting", container);
                    client.umount(container).await.context("failed to umount")?;
                    info!("{}: awaiting umount", container);
                    await_container_state(&mut client, container, |state| !state.mounted).await?;
                    info!("{}: umounted", container);
                }

                if stop.is_cancelled() {
                    return Result::<u64>::Ok(iteration);
                }
            }
            unreachable!()
        })
        .then(|r| ready(r.expect("task error")));

        tasks.push(task);
    }

    info!("Starting {} tasks", tasks.len());

    let mut tasks = try_join_all(tasks);
    let ctrl_c = tokio::signal::ctrl_c();
    let duration = opt
        .duration
        .map(time::sleep)
        .map(Either::Left)
        .unwrap_or_else(|| Either::Right(pending::<()>()));

    let result = select! {
        _ = duration => {
            info!("Stopping because test duration exceeded");
            stop.cancel();
            tasks.await
        }
        _ = ctrl_c => {
            info!("Stopping because of ctrlc");
            stop.cancel();
            tasks.await
        }
        r = &mut tasks => r,
    };

    println!("iterations: {}", result?.iter().sum::<u64>());
    Ok(())
}

/// Install and uninstall an npk in a loop
async fn install_uninstall(opt: &Opt) -> Result<()> {
    let connect_timeout = time::Duration::from_secs(30);
    let mut client = Client::new(io(&opt.url).await?, Some(10), connect_timeout).await?;

    let timeout = opt
        .duration
        .map(|d| Either::Left(time::sleep(d)))
        .unwrap_or_else(|| Either::Right(pending()));
    pin!(timeout);

    let npk = opt
        .npk
        .as_ref()
        .ok_or_else(|| anyhow!("Missing npk argument"))?;
    let repository = opt
        .repository
        .as_ref()
        .ok_or_else(|| anyhow!("Missing repository argument"))?;

    // Initial install - everyhing beyond is notification triggered
    client.install_file(npk, repository).await?;

    loop {
        select! {
            _ = &mut timeout => break Ok(()),
            n = client.next() => {
                match n {
                    Some(Ok(model::Notification::Install ( container ))) => {
                        client.uninstall(container, true).await?;
                    }
                    Some(Ok(model::Notification::Uninstall( _ ))) => {
                        client.install_file(npk, repository).await?;
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => break Err(e.into()),
                    None => break Err(anyhow!("Runtime closed the connection")),
                }
            }
        }
    }
}

/// Monkey testing: randmon action on random container
async fn monkey(opt: &Opt) -> Result<()> {
    debug!("Getting list of containers");
    let mut client = Client::new(io(&opt.url).await?, None, time::Duration::from_secs(30)).await?;

    let containers = client.list().await?;
    let mut rng = rand::thread_rng();

    let duration = opt
        .duration
        .map(time::sleep)
        .map(Either::Left)
        .unwrap_or_else(|| Either::Right(pending::<()>()));
    pin!(duration);

    let mut delay = opt
        .random_delay
        .map(time::interval)
        .map(IntervalStream::new)
        .map(|s| s.map(drop))
        .map(Either::Left)
        .unwrap_or_else(|| Either::Right(repeat(())));

    loop {
        select! {
            _ = &mut duration => {
                info!("Stopping because test duration exceeded");
                break Ok(());
            }
            _ = &mut delay.next() => {
                let container = containers
                    .iter()
                    .choose(&mut rng)
                    .expect("failed to select random container");

                match rand::random() {
                    MonkeyAction::Start => {
                        info!("Trying to start {}", container);
                        client.start(container).map(drop).await;
                    }
                    MonkeyAction::Kill(signal) => {
                        info!("Trying to kill {} with signal {}", container, signal);
                        client.kill(container, signal).map(drop).await;
                    }
                    MonkeyAction::Mount => {
                        info!("Trying to mount {}", container);
                        client.mount(container).map(drop).await;
                    }
                    MonkeyAction::Umount => {
                        info!("Trying to umount {}", container);
                        client.umount(container).map(drop).await;
                    }
                };
            }
        }
    }
}

/// Poll the container state until the process context is Some(_)
async fn await_container_state(
    client: &mut Client<Box<(dyn N + Sync)>>,
    container: &Container,
    mut pred: impl FnMut(ContainerData) -> bool,
) -> Result<()> {
    loop {
        let data = client.inspect(container).await?;
        if pred(data) {
            break Ok(());
        } else {
            yield_now().await;
        }
    }
}
