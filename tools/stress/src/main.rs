use anyhow::{anyhow, Context, Result};
use clap::Parser;
use futures::{
    future::{self, pending, ready, try_join_all, Either},
    FutureExt, StreamExt,
};
use humantime::parse_duration;
use itertools::Itertools;
use log::{debug, info};
use northstar::api::{
    client::{self, Client},
    model::{self, Container, ExitStatus, Notification},
};
use std::{path::PathBuf, str::FromStr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, UnixStream},
    pin, select,
    sync::Barrier,
    task, time,
};
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Clone, Debug, PartialEq)]
enum Mode {
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
            "mount-umount" => Ok(Mode::MountUmount),
            "start-stop" => Ok(Mode::StartStop),
            "start-stop-umount" => Ok(Mode::StartStopUmount),
            "mount-start-stop-umount" => Ok(Mode::StartStopUmount),
            "install-uninstall" => Ok(Mode::InstallUninstall),
            _ => Err("invalid mode"),
        }
    }
}

#[derive(Debug, Parser)]
#[clap(
    name = "stress",
    about = "Manual stress test the start and stop of Nortstar containers"
)]
struct Opt {
    /// Runtime address
    #[clap(short, long, default_value = "tcp://localhost:4200")]
    url: url::Url,

    /// Duration to run the test for in seconds
    #[clap(short, long, parse(try_from_str = parse_duration))]
    duration: Option<Duration>,

    /// Random delay between each iteration within 0..value ms
    #[clap(short, long, parse(try_from_str = parse_duration))]
    random: Option<Duration>,

    /// Single client
    #[clap(short, long)]
    single: bool,

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
    #[clap(long)]
    initial_random_delay: Option<u64>,

    /// Notification timeout in seconds
    #[clap(short, long, parse(try_from_str = parse_duration), default_value = "60s")]
    timeout: Duration,
}

pub trait N: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> N for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

async fn io(url: &Url) -> Result<Box<dyn N>> {
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

            Ok(Box::new(stream) as Box<dyn N>)
        }
        "unix" => {
            let stream = time::timeout(timeout, UnixStream::connect(url.path()))
                .await
                .context("failed to connect")??;
            Ok(Box::new(stream) as Box<dyn N>)
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
    debug!("random: {:?}", opt.random);
    debug!("timeout: {:?}", opt.timeout);

    if opt.mode == Mode::InstallUninstall {
        return install_uninstall(&opt).await;
    }

    // Get a list of installed applications
    debug!("Getting list of startable containers");
    let mut client =
        client::Client::new(io(&opt.url).await?, None, time::Duration::from_secs(30)).await?;
    let containers = client
        .containers()
        .await?
        .iter()
        .filter(|c| c.manifest.init.is_some())
        .map(|c| c.container.clone())
        .sorted()
        .collect::<Vec<_>>();
    drop(client);

    let mut tasks = Vec::new();
    let stop = CancellationToken::new();

    if opt.single {
        let stop = stop.clone();
        let task = task::spawn(async move {
            let mut client = client::Client::new(
                io(&opt.url).await?,
                Some(containers.len() * 3),
                time::Duration::from_secs(30),
            )
            .await?;

            let mut iterations = 0;
            loop {
                for container in &containers {
                    info!("{}: start", container);
                    client.start(container).await?;
                }
                for container in &containers {
                    info!("{}: stopping", container);
                    client
                        .kill(container.clone(), 15)
                        .await
                        .context("failed to stop container")?;
                    info!("{}: waiting for termination", container);
                    let stopped =
                        Notification::Exit(container.clone(), ExitStatus::Signalled { signal: 15 });
                    await_notification(&mut client, stopped, opt.timeout).await?;
                }

                iterations += containers.len();

                if stop.is_cancelled() {
                    break Ok(iterations);
                }
            }
        })
        .then(|r| match r {
            Ok(r) => ready(r),
            Err(e) => ready(Result::<usize>::Err(anyhow!("task error: {}", e))),
        });

        tasks.push(futures::future::Either::Right(task));
    } else {
        // Sync the start of all tasks
        let start_barrier = Arc::new(Barrier::new(containers.len()));

        for container in &containers {
            let container = container.clone();
            let initial_random_delay = opt.initial_random_delay;
            let mode = opt.mode.clone();
            let random = opt.random;
            let start_barrier = start_barrier.clone();
            let timeout = opt.timeout;
            let stop = stop.clone();
            let url = opt.url.clone();

            debug!("Spawning task for {}", container);
            let task = task::spawn(async move {
                let mut client =
                    client::Client::new(io(&url).await?, Some(1000), time::Duration::from_secs(30))
                        .await?;

                if let Some(initial_delay) = initial_random_delay {
                    time::sleep(time::Duration::from_millis(
                        rand::random::<u64>() % initial_delay,
                    ))
                    .await;
                }

                let mut iterations = 0usize;

                start_barrier.wait().await;

                loop {
                    iteration(&mode, &container, &mut client, timeout, random).await?;
                    iterations += 1;

                    if stop.is_cancelled() {
                        break Ok(iterations);
                    }
                }
            })
            .then(|r| match r {
                Ok(r) => ready(r),
                Err(e) => ready(Result::<usize>::Err(anyhow!("task error: {}", e))),
            });

            tasks.push(Either::Left(task));
        }
    }

    info!("Starting {} tasks", tasks.len());

    let mut tasks = try_join_all(tasks);
    let ctrl_c = tokio::signal::ctrl_c();
    let duration = opt
        .duration
        .map(time::sleep)
        .map(Either::Left)
        .unwrap_or_else(|| Either::Right(future::pending::<()>()));

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

    info!("Total iterations: {}", result?.iter().sum::<usize>());
    Ok(())
}

async fn iteration(
    mode: &Mode,
    container: &Container,
    client: &mut Client<Box<dyn N>>,
    timeout: Duration,
    random: Option<Duration>,
) -> Result<()> {
    if *mode == Mode::MountStartStopUmount || *mode == Mode::MountUmount {
        info!("{} mount", &container);
        client.mount(container).await?;
    }

    if *mode != Mode::MountUmount {
        info!("{}: start", container);
        client.start(container).await?;
        let started = Notification::Started(container.clone());
        await_notification(client, started, timeout).await?;
    }

    if let Some(delay) = random {
        info!("{}: sleeping for {:?}", container, delay);
        time::sleep(delay).await;
    }

    if *mode != Mode::MountUmount {
        info!("{}: stopping", container);
        client
            .kill(container.clone(), 15)
            .await
            .context("failed to stop container")?;

        info!("{}: waiting for termination", container);
        let stopped = Notification::Exit(container.clone(), ExitStatus::Signalled { signal: 15 });
        await_notification(client, stopped, timeout).await?;
    }

    // Check if we need to umount
    if *mode != Mode::StartStop {
        info!("{}: umounting", container);
        client.umount(container).await.context("failed to umount")?;
    }

    Ok(())
}

/// Wait for a `notification` for `duration` seconds or timeout
async fn await_notification<T: AsyncRead + AsyncWrite + Unpin>(
    client: &mut Client<T>,
    notification: Notification,
    duration: Duration,
) -> Result<()> {
    time::timeout(duration, async {
        loop {
            match client.next().await {
                Some(Ok(n)) if n == notification => break Ok(()),
                Some(Ok(_)) => continue,
                Some(Err(e)) => break Err(e.into()),
                None => break Err(anyhow!("Notification stream closed")),
            }
        }
    })
    .await
    .with_context(|| format!("failed to wait for notification: {:?}", notification))?
}

/// Install and uninstall an npk in a loop
async fn install_uninstall(opt: &Opt) -> Result<()> {
    let timeout = time::Duration::from_secs(30);
    let mut client = client::Client::new(io(&opt.url).await?, Some(10), timeout).await?;

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
                        client.uninstall(container).await?;
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
