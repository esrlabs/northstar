//! Controls Northstar runtime instances

use super::{containers::*, logger};
use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use northstar::{
    api::{
        client::Client,
        model::{Container, ExitStatus, Notification},
    },
    common::non_null_string::NonNullString,
    runtime::{
        self,
        config::{self, Config, RepositoryType},
    },
};
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
};
use tempfile::{NamedTempFile, TempDir};
use tokio::{fs, net::UnixStream, pin, select, time};

pub struct Northstar {
    /// Runtime configuration
    pub config: Config,
    /// Runtime console address (Unix socket)
    pub console: String,
    /// Client instance
    client: northstar::api::client::Client<UnixStream>,
    /// Runtime instance
    runtime: runtime::Runtime,
    /// Tmpdir for NPK dumps
    tmpdir: TempDir,
}

impl std::ops::Deref for Northstar {
    type Target = Client<UnixStream>;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl std::ops::DerefMut for Northstar {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}

impl Northstar {
    /// Launches an instance of Northstar
    pub async fn launch() -> Result<Northstar> {
        let pid = std::process::id();
        let tmpdir = tempfile::Builder::new().prefix("northstar-").tempdir()?;

        let run_dir = tmpdir.path().join("run");
        fs::create_dir(&run_dir).await?;
        let data_dir = tmpdir.path().join("data");
        fs::create_dir(&data_dir).await?;
        let log_dir = tmpdir.path().join("log");
        fs::create_dir(&log_dir).await?;
        let test_repository = tmpdir.path().join("test");
        fs::create_dir(&test_repository).await?;
        let example_key = tmpdir.path().join("key.pub");
        fs::write(&example_key, include_bytes!("../../examples/northstar.pub")).await?;

        let mut repositories = HashMap::new();
        repositories.insert(
            "test-0".into(),
            config::Repository {
                r#type: RepositoryType::Memory,
                key: Some(example_key.clone()),
            },
        );
        repositories.insert(
            "test-1".into(),
            config::Repository {
                r#type: RepositoryType::Memory,
                key: Some(example_key.clone()),
            },
        );

        let console = format!(
            "{}/northstar-{}",
            tmpdir.path().display(),
            std::process::id()
        );
        let console_url = url::Url::parse(&format!("unix://{}", console))?;

        let config = Config {
            console: Some(vec![console_url.clone()]),
            run_dir,
            data_dir: data_dir.clone(),
            log_dir,
            mount_parallel: 10,
            cgroup: NonNullString::try_from(format!("northstar-{}", pid)).unwrap(),
            repositories,
            debug: None,
        };

        // Start the runtime
        let runtime = runtime::Runtime::start(config.clone())
            .await
            .context("Failed to start runtime")?;
        // Wait until the console is up and running
        super::logger::assume("Started console on", 5u64).await?;

        // Connect to the runtime
        let io = UnixStream::connect(&console)
            .await
            .expect("Failed to connect to console");
        let client = Client::new(io, Some(1000), time::Duration::from_secs(30)).await?;
        // Wait until a successful connection
        logger::assume("Client .* connected", 5u64).await?;

        Ok(Northstar {
            config,
            console,
            client,
            runtime,
            tmpdir,
        })
    }

    /// Connect a new client instance to the runtime
    pub async fn client(&self) -> Result<Client<UnixStream>> {
        let io = UnixStream::connect(&self.console)
            .await
            .context("Failed to connect to console")?;
        Client::new(io, Some(1000), time::Duration::from_secs(30))
            .await
            .context("Failed to create client")
    }

    /// Launches an instance of Northstar with the test container and
    /// resource installed.
    pub async fn launch_install_test_container() -> Result<Northstar> {
        let mut runtime = Self::launch().await?;
        runtime.install_test_resource().await?;
        runtime.install_test_container().await?;
        Ok(runtime)
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

    pub async fn shutdown(self) -> Result<()> {
        // Dropping the client closes the connection to the runtime
        drop(self.client);

        // Stop the runtime
        self.runtime
            .shutdown()
            .await
            .context("Failed to stop the runtime")?;

        logger::assume("Closed listener", 5u64).await?;

        // Remove the tmpdir
        self.tmpdir.close().expect("Failed to remove tmpdir");
        Ok(())
    }

    // Install a npk from a buffer
    pub async fn install(&mut self, npk: &[u8], repository: &str) -> Result<()> {
        let f = NamedTempFile::new_in(self.tmpdir.path())?;
        fs::write(&f, npk).await?;
        self.client.install(f.path(), repository).await?;
        Ok(())
    }

    /// Install the test container and wait for the notification
    pub async fn install_test_container(&mut self) -> Result<()> {
        self.install(TEST_CONTAINER_NPK, "test-0")
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
        self.install(TEST_RESOURCE_NPK, "test-0")
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
