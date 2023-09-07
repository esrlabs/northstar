//! Controls Northstar runtime instances

use super::{containers::*, logger};
use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use nanoid::nanoid;
use nix::sys::signal::Signal::SIGTERM;
use northstar_client::Connection;
use northstar_runtime::{
    api::{
        codec::framed,
        model::{Container, ExitStatus, Notification},
    },
    common::non_nul_string::NonNulString,
    npk::manifest::console::Permissions,
    runtime::{
        config::{self, Console, ConsoleGlobal},
        Runtime as Northstar,
    },
};
use std::{
    convert::TryFrom,
    fs,
    os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixStream as StdUnixStream},
    },
};
use tempfile::TempDir;
use tokio::{
    net::{self, UnixStream},
    pin, select, task, time,
};
use url::Url;

pub fn console_url() -> Url {
    Url::parse(&format!(
        "unix+abstract://northstar-{}-full",
        std::process::id()
    ))
    .unwrap()
}

pub enum Runtime {
    Created(Northstar, TempDir),
    Started(Northstar, TempDir),
}

impl Runtime {
    pub fn new() -> Result<Runtime> {
        let tmpdir = tempfile::Builder::new().prefix("northstar-").tempdir()?;
        let run_dir = tmpdir.path().join("run");
        fs::create_dir(&run_dir)?;
        let data_dir = tmpdir.path().join("data");
        fs::create_dir(&data_dir)?;
        let socket_dir = tmpdir.path().join("sockets");
        fs::create_dir(&socket_dir)?;
        let test_repository = tmpdir.path().join("test");
        fs::create_dir(&test_repository)?;
        let test_repository_limited_num = tmpdir.path().join("test_limited_num");
        fs::create_dir(&test_repository_limited_num)?;
        let test_repository_limited_size = tmpdir.path().join("test_limited_size");
        fs::create_dir(&test_repository_limited_size)?;
        let example_key = tmpdir.path().join("key.pub");
        fs::write(&example_key, include_bytes!("../../examples/northstar.pub"))?;

        let repositories = [
            (
                "mem".into(),
                config::Repository {
                    r#type: config::RepositoryType::Memory,
                    key: Some(example_key.clone()),
                    mount_on_start: false,
                    capacity_num: None,
                    capacity_size: None,
                },
            ),
            (
                "fs".into(),
                config::Repository {
                    r#type: config::RepositoryType::Fs {
                        dir: test_repository,
                    },
                    key: Some(example_key.clone()),
                    mount_on_start: false,
                    capacity_num: None,
                    capacity_size: None,
                },
            ),
            (
                "limited_capacity_num_mem".into(),
                config::Repository {
                    r#type: config::RepositoryType::Memory,
                    key: Some(example_key.clone()),
                    mount_on_start: false,
                    capacity_num: Some(1),
                    capacity_size: None,
                },
            ),
            (
                "limited_capacity_num_fs".into(),
                config::Repository {
                    r#type: config::RepositoryType::Fs {
                        dir: test_repository_limited_num,
                    },
                    key: Some(example_key.clone()),
                    mount_on_start: false,
                    capacity_num: Some(1),
                    capacity_size: None,
                },
            ),
            (
                "limited_capacity_size_mem".into(),
                config::Repository {
                    r#type: config::RepositoryType::Memory,
                    key: Some(example_key.clone()),
                    mount_on_start: false,
                    capacity_num: None,
                    capacity_size: Some(1000),
                },
            ),
            (
                "limited_capacity_size_fs".into(),
                config::Repository {
                    r#type: config::RepositoryType::Fs {
                        dir: test_repository_limited_size,
                    },
                    key: Some(example_key),
                    mount_on_start: false,
                    capacity_num: None,
                    capacity_size: Some(1000),
                },
            ),
        ]
        .into();

        let config = config::Config {
            run_dir,
            data_dir,
            socket_dir,
            event_buffer_size: 128,
            notification_buffer_size: 128,
            loop_device_timeout: time::Duration::from_secs(10),
            cgroup: NonNulString::try_from(format!("northstar-{}", nanoid!())).unwrap(),
            repositories,
            console: Console {
                global: Some(ConsoleGlobal {
                    bind: console_url(),
                    permissions: Permissions::full(),
                    options: None,
                }),
                ..Default::default()
            },
            debug: Some(config::Debug {
                commands: vec!["sudo strace -c -p <PID>".into()],
            }),
        };
        let runtime = Northstar::new(config)?;

        Ok(Runtime::Created(runtime, tmpdir))
    }

    pub async fn start(self) -> Result<(Runtime, Client)> {
        if let Runtime::Created(launcher, tmpdir) = self {
            let runtime = launcher.start().await?;
            logger::assume("Runtime up and running", 10u64).await?;

            let client = Client::connect(&console_url()).await?;

            Ok((Runtime::Started(runtime, tmpdir), client))
        } else {
            anyhow::bail!("Runtime is already started")
        }
    }

    pub async fn shutdown(self) -> Result<()> {
        if let Runtime::Started(runtime, tmpdir) = self {
            runtime.shutdown().await?;
            logger::assume("Shutdown complete", 5u64).await?;
            tmpdir.close()?;
        }
        Ok(())
    }
}

pub struct Client {
    client: northstar_client::Client<UnixStream>,
}

impl std::ops::Deref for Client {
    type Target = northstar_client::Client<UnixStream>;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl std::ops::DerefMut for Client {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}

impl Client {
    /// Connect stream.
    pub async fn stream(url: &Url) -> Result<net::UnixStream> {
        let addr = SocketAddr::from_abstract_name(url.path())?;
        let stream = task::spawn_blocking(move || StdUnixStream::connect_addr(&addr)).await??;
        stream.set_nonblocking(true)?;
        let stream = net::UnixStream::from_std(stream)?;
        Ok(stream)
    }

    /// Framed connection.
    pub async fn framed(url: &Url) -> Result<Connection<UnixStream>> {
        let stream = Self::stream(url).await?;
        Ok(framed(stream))
    }

    /// Connect a northstar client instance.
    pub async fn connect(url: &Url) -> Result<Client> {
        let stream = Self::stream(url).await?;
        let client = northstar_client::Client::new(stream, Some(1000)).await?;

        // Wait until a successful connection
        logger::assume("Client .* connected", 5u64).await?;

        Ok(Client { client })
    }

    /// Stop a container.
    pub async fn stop(&mut self, container: &str, timeout: u64) -> Result<()> {
        self.client.kill(container, SIGTERM as i32).await?;
        self.assume_exit(
            container,
            ExitStatus::Signalled {
                signal: SIGTERM as u32,
            },
            timeout,
        )
        .await
    }

    /// Shutdown the runtime.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.client.shutdown().await;
        logger::assume("Shutdown complete", 5u64).await
    }

    // Install a npk from a buffer.
    pub async fn install(&mut self, npk: &[u8], repository: &str) -> Result<()> {
        self.client
            .install(npk, npk.len() as u64, repository)
            .await?;
        Ok(())
    }

    /// Install the test container and wait for the notification.
    pub async fn install_test_container(&mut self) -> Result<()> {
        self.install(&TEST_CONTAINER_NPK, "mem")
            .await
            .context("failed to install test container")?;

        self.assume_notification(|n| matches!(n, Notification::Install { .. }), 15)
            .await
            .context("failed to wait for test container install notification")
    }

    /// Uninstall the test container and wait for the notification.
    pub async fn uninstall_test_container(&mut self) -> Result<()> {
        self.client
            .uninstall("test-container:0.0.1", true)
            .await
            .context("failed to uninstall test container")?;
        self.assume_notification(|n| matches!(n, Notification::Uninstall { .. }), 15)
            .await
            .context("failed to wait for test container uninstall notification")
    }

    /// Install the test resource and wait for the notification.
    pub async fn install_test_resource(&mut self) -> Result<()> {
        self.install(&TEST_RESOURCE_NPK, "mem")
            .await
            .context("failed to install test resource")?;
        self.assume_notification(|n| matches!(n, Notification::Install { .. }), 15)
            .await
            .context("failed to wait for test resource install notification")
    }

    /// Uninstall the test resource and wait for the notification.
    pub async fn uninstall_test_resource(&mut self) -> Result<()> {
        self.client
            .uninstall("test-resource:0.0.1", true)
            .await
            .context("failed to uninstall test resource")?;
        self.assume_notification(|n| matches!(n, Notification::Uninstall { .. }), 15)
            .await
            .context("failed to wait for test resource uninstall notification")
    }

    /// Wait for a notification that matches `pred`. Notifications are buffered in the `Client`.
    pub async fn assume_notification<F>(&mut self, mut pred: F, timeout: u64) -> Result<()>
    where
        F: FnMut(&Notification) -> bool,
    {
        let timeout = time::sleep(time::Duration::from_secs(timeout));
        pin!(timeout);

        loop {
            select! {
                _ = &mut timeout => break Err(anyhow!("timeout waiting for notification")),
                notification = self.client.next() => {
                    match notification {
                        Some(Ok(n)) if pred(&n) => break Ok(()),
                        Some(_) => continue,
                        None => break Err(anyhow!("client connection closed")),
                    }
                }
            }
        }
    }

    /// Wait for a notification that `container` exited with `exit_status`.
    pub async fn assume_exit(
        &mut self,
        container: &str,
        exit_status: ExitStatus,
        timeout: u64,
    ) -> Result<()> {
        let container = Container::try_from(container)?;
        let n = |n: &Notification| matches!(n, Notification::Exit(c, s) if container == *c && exit_status == *s);
        self.assume_notification(n, timeout).await
    }

    /// Wait for a notification that `container` exited with exit code 0.
    pub async fn assume_exit_success(&mut self, container: &str, timeout: u64) -> Result<()> {
        let exit_status = ExitStatus::Exit { code: 0 };
        self.assume_exit(container, exit_status, timeout).await
    }
}
