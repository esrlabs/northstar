//! Controls Northstar runtime instances

use super::{containers::*, logger};
use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use nanoid::nanoid;
use northstar::{
    api::{
        client,
        model::{Container, ExitStatus, Notification},
    },
    common::non_null_string::NonNullString,
    runtime::{
        config::{self, Config, RepositoryType},
        Runtime as Northstar,
    },
};
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
};
use tempfile::{NamedTempFile, TempDir};
use tokio::{fs, net::UnixStream, pin, select, time};

pub static mut CLIENT: Option<Client> = None;

pub fn client() -> &'static mut Client {
    unsafe { CLIENT.as_mut().unwrap() }
}

pub fn console() -> url::Url {
    let console = std::env::temp_dir().join(format!("northstar-{}", std::process::id()));
    url::Url::parse(&format!("unix://{}", console.display())).unwrap()
}

pub enum Runtime {
    Created(Northstar, TempDir),
    Started(Northstar, TempDir),
}

impl Runtime {
    pub fn new() -> Result<Runtime> {
        let tmpdir = tempfile::Builder::new().prefix("northstar-").tempdir()?;
        let run_dir = tmpdir.path().join("run");
        std::fs::create_dir(&run_dir)?;
        let data_dir = tmpdir.path().join("data");
        std::fs::create_dir(&data_dir)?;
        let log_dir = tmpdir.path().join("log");
        std::fs::create_dir(&log_dir)?;
        let test_repository = tmpdir.path().join("test");
        std::fs::create_dir(&test_repository)?;
        let example_key = tmpdir.path().join("key.pub");
        std::fs::write(&example_key, include_bytes!("../../examples/northstar.pub"))?;

        let mut repositories = HashMap::new();
        repositories.insert(
            "mem".into(),
            config::Repository {
                mount_on_start: false,
                r#type: RepositoryType::Memory,
                key: Some(example_key.clone()),
            },
        );
        repositories.insert(
            "fs".into(),
            config::Repository {
                mount_on_start: false,
                r#type: RepositoryType::Fs {
                    dir: test_repository,
                },
                key: Some(example_key),
            },
        );

        let config = Config {
            console: Some(vec![console()]),
            run_dir,
            data_dir,
            log_dir,
            cgroup: NonNullString::try_from(format!("northstar-{}", nanoid!())).unwrap(),
            repositories,
            debug: None,
        };
        let b = Northstar::new(config)?;

        Ok(Runtime::Created(b, tmpdir))
    }

    pub async fn start(self) -> Result<Runtime> {
        if let Runtime::Created(launcher, tmpdir) = self {
            let runtime = launcher.start().await?;
            logger::assume("Runtime up and running", 10u64).await?;

            unsafe {
                CLIENT = Some(Client::new().await?);
            }

            Ok(Runtime::Started(runtime, tmpdir))
        } else {
            anyhow::bail!("Runtime is already started")
        }
    }
}

pub struct Client {
    /// Client instance
    client: northstar::api::client::Client<UnixStream>,
}

impl std::ops::Deref for Client {
    type Target = client::Client<UnixStream>;

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
    /// Launches an instance of Northstar
    pub async fn new() -> Result<Client> {
        // Connect to the runtime
        let io = UnixStream::connect(console().path())
            .await
            .expect("Failed to connect to console");
        let client = client::Client::new(io, Some(1000), time::Duration::from_secs(30)).await?;
        // Wait until a successful connection
        logger::assume("Client .* connected", 5u64).await?;

        Ok(Client { client })
    }

    /// Connect a new client instance to the runtime
    pub async fn client(&self) -> Result<client::Client<UnixStream>> {
        let io = UnixStream::connect(console().path())
            .await
            .context("Failed to connect to console")?;
        client::Client::new(io, Some(1000), time::Duration::from_secs(30))
            .await
            .context("Failed to create client")
    }

    pub async fn stop(&mut self, container: &str, timeout: u64) -> Result<()> {
        self.client.kill(container, 15).await?;
        let container: Container = container.try_into()?;
        self.assume_notification(
            |n| {
                n == &Notification::Exit {
                    container: container.clone(),
                    status: ExitStatus::Signalled { signal: 15 },
                }
            },
            timeout,
        )
        .await?;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        drop(self.client.shutdown().await);
        logger::assume("Shutdown complete", 5u64).await?;
        Ok(())
    }

    // Install a npk from a buffer
    pub async fn install(&mut self, npk: &[u8], repository: &str) -> Result<()> {
        let f = NamedTempFile::new()?;
        fs::write(&f, npk).await?;
        self.client.install(f.path(), repository).await?;
        Ok(())
    }

    /// Install the test container and wait for the notification
    pub async fn install_test_container(&mut self) -> Result<()> {
        self.install(TEST_CONTAINER_NPK, "mem")
            .await
            .context("Failed to install test container")?;

        self.assume_notification(|n| matches!(n, Notification::Install { .. }), 15)
            .await
            .context("Failed to wait for test container install notification")
    }

    /// Uninstall the test container and wait for the notification
    pub async fn uninstall_test_container(&mut self) -> Result<()> {
        self.client
            .uninstall("test-container:0.0.1")
            .await
            .context("Failed to uninstall test container")?;
        self.assume_notification(|n| matches!(n, Notification::Uninstall { .. }), 15)
            .await
            .context("Failed to wait for test container uninstall notification")
    }

    /// Install the test resource and wait for the notification
    pub async fn install_test_resource(&mut self) -> Result<()> {
        self.install(TEST_RESOURCE_NPK, "mem")
            .await
            .context("Failed to install test resource")?;
        self.assume_notification(|n| matches!(n, Notification::Install { .. }), 15)
            .await
            .context("Failed to wait for test resource install notification")
    }

    /// Uninstall the test resource and wait for the notification
    pub async fn uninstall_test_resource(&mut self) -> Result<()> {
        self.client
            .uninstall("test-resource:0.0.1")
            .await
            .context("Failed to uninstall test resource")?;
        self.assume_notification(|n| matches!(n, Notification::Uninstall { .. }), 15)
            .await
            .context("Failed to wait for test resource uninstall notification")
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
                _ = &mut timeout => break Err(anyhow!("Timeout waiting for notification")),
                notification = self.client.next() => {
                    match notification {
                        Some(Ok(n)) if pred(&n) => break Ok(()),
                        Some(_) => continue,
                        None => break Err(anyhow!("Client connection closed")),
                    }
                }
            }
        }
    }
}
