// Copyright (c) 2019 - 2020 ESRLabs
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

use super::{
    config::Config,
    keys,
    npk::Container,
    process::{ExitStatus, Process},
};
use crate::{
    api::{InstallationResult, Message, MessageId, Notification},
    manifest::{Manifest, Mount, Name, Version},
    runtime::{
        error::{Error, InstallFailure},
        npk,
        npk::extract_manifest,
        Event, EventTx, NotificationTx,
    },
};
use anyhow::{anyhow, Result};
use async_std::{
    fs,
    path::{Path, PathBuf},
    stream::StreamExt,
    sync,
};
use ed25519_dalek::PublicKey;
use log::{info, warn};
use std::{
    collections::{HashMap, HashSet},
    fmt, iter, result, time,
};
use time::Duration;

#[derive(Debug)]
pub struct State {
    events_tx: EventTx,
    notification_tx: NotificationTx,
    pub signing_keys: HashMap<String, PublicKey>,
    pub applications: HashMap<Name, Application>,
    pub config: Config,
}

#[derive(Debug)]
pub struct Application {
    container: Container,
    process: Option<ProcessContext>,
}

#[derive(Debug)]
pub struct ProcessContext {
    process: Box<dyn Process>,
    incarnation: u32,
    start_timestamp: time::Instant,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    cgroups: Option<super::linux::cgroups::CGroups>,
}

impl ProcessContext {
    pub fn process(&self) -> &dyn Process {
        self.process.as_ref()
    }

    pub fn process_mut(&mut self) -> &mut dyn Process {
        self.process.as_mut()
    }

    pub fn uptime(&self) -> Duration {
        self.start_timestamp.elapsed()
    }
}

impl Application {
    pub fn new(container: Container) -> Application {
        Application {
            container,
            process: None,
        }
    }

    pub fn name(&self) -> &Name {
        &self.manifest().name
    }

    pub fn version(&self) -> &Version {
        &self.manifest().version
    }

    pub fn manifest(&self) -> &Manifest {
        &self.container.manifest
    }

    pub fn container(&self) -> &Container {
        &self.container
    }

    pub fn process_context(&self) -> Option<&ProcessContext> {
        self.process.as_ref()
    }

    pub fn is_running(&self) -> bool {
        self.process.is_some()
    }
}

impl fmt::Display for Application {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.manifest().name, self.version())
    }
}

impl State {
    /// Create a new empty State instance
    pub async fn new(
        config: &Config,
        tx: EventTx,
        notification_tx: NotificationTx,
    ) -> Result<State> {
        // Load keys for manifest verification
        let key_dir: PathBuf = config.directories.key_dir.clone().into();
        let signing_keys = keys::load(&key_dir).await?;

        Ok(State {
            events_tx: tx,
            notification_tx,
            signing_keys,
            applications: HashMap::new(),
            config: config.clone(),
        })
    }

    /// Return an owned copy of the main loop tx handle
    pub fn _event_tx(&self) -> EventTx {
        self.events_tx.clone()
    }

    /// Return an iterator over all known applications
    pub fn applications(&self) -> impl iter::Iterator<Item = &Application> {
        self.applications.values()
    }

    /// Try to find a application with name `name`
    pub fn application(&mut self, name: &str) -> Option<&Application> {
        self.applications.get(name)
    }

    /// Add a container instance the list of known containers
    pub fn add(&mut self, container: Container) -> Result<(), InstallFailure> {
        let name = container.manifest.name.clone();
        if self.applications.get(&name).is_some() {
            return Err(InstallFailure::ApplicationAlreadyInstalled(name));
        }
        let app = Application::new(container);
        self.applications.insert(name, app);
        Ok(())
    }

    pub async fn start(&mut self, name: &str) -> result::Result<(), Error> {
        // Setup set of available resources
        let resources = self
            .applications
            .values()
            .filter_map(|app| {
                if app.container.is_resource_container() {
                    Some(app.container.manifest.name.clone())
                } else {
                    None
                }
            })
            .collect::<HashSet<Name>>();

        // Look for app
        let app = if let Some(app) = self.applications.get_mut(name) {
            app
        } else {
            return Err(Error::ApplicationNotFound);
        };

        // Check if application is already running
        if app.process.is_some() {
            warn!("Application {} is already running", app.manifest().name);
            return Err(Error::ApplicationRunning(vec![app.manifest().name.clone()]));
        }

        // Check if app is a resource container that cannot be started
        if app.container.is_resource_container() {
            warn!("Cannot start resource containers ({})", app);
            return Err(Error::ApplicationNotFound);
        }

        // Check for all required resources
        for mount in app.container.manifest.mounts.iter() {
            if let Mount::Resource { name, .. } = mount {
                if !resources.contains(name) {
                    return Err(Error::MissingResource(name.clone()));
                }
            }
        }

        // Spawn process
        info!("Starting {}", app);

        // Android and Linux
        #[cfg(any(target_os = "android", target_os = "linux"))]
        let process = super::process::minijail::MinijailProcess::start(
            &app.container,
            self.events_tx.clone(),
            self.config.directories.run_dir.as_path().into(),
            self.config.directories.data_dir.as_path().into(),
            self.config.container_uid,
            self.config.container_gid,
        )
        .await
        .map_err(Error::ProcessError)?;

        // Not Android or Linux
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        let process = super::process::os::OsProcess::start(&app.container, self.tx.clone())
            .await
            .map_err(Error::ProcessError)?;

        let process = Box::new(process) as Box<dyn Process>;

        // CGroups
        #[cfg(any(target_os = "android", target_os = "linux"))]
        let cgroups = if let Some(ref c) = app.manifest().cgroups {
            log::debug!("Creating cgroup configuration for {}", app);
            let cgroups = crate::runtime::linux::cgroups::CGroups::new(
                &self.config.cgroups,
                app.name(),
                c,
                self.events_tx.clone(),
            )
            .await
            .map_err(Error::ProcessError)?;

            log::debug!("Assigning {} to cgroup {}", process.pid(), app);
            cgroups
                .assign(process.pid())
                .await
                .map_err(Error::ProcessError)?;
            Some(cgroups)
        } else {
            None
        };

        app.process = Some(ProcessContext {
            process,
            incarnation: 0,
            start_timestamp: time::Instant::now(),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            cgroups,
        });
        info!("Started {}", app);

        Ok(())
    }

    /// Stop a application. Timeout specifies the time until the process is
    /// SIGKILLed if it doesn't exit when receiving a SIGTERM
    pub async fn stop(&mut self, name: &str, timeout: Duration) -> result::Result<(), Error> {
        if let Some(app) = self.applications.get_mut(name) {
            if let Some(mut context) = app.process.take() {
                info!("Stopping {}", app);
                let status = context
                    .process
                    .stop(timeout)
                    .await
                    .map_err(Error::ProcessError)?;

                #[cfg(any(target_os = "android", target_os = "linux"))]
                {
                    if let Some(cgroups) = context.cgroups {
                        log::debug!("Destroying cgroup configuration of {}", app);
                        cgroups.destroy().await.map_err(Error::ProcessError)?;
                    }
                }

                info!("Stopped {} {:?}", app, status);
                Ok(())
            } else {
                warn!("Application {} is not running", app);
                Err(Error::ApplicationNotRunning)
            }
        } else {
            Err(Error::ApplicationNotFound)
        }
    }

    pub async fn shutdown(&self) -> result::Result<(), Error> {
        if self
            .applications
            .values()
            .all(|app| app.process_context().is_none())
        {
            // remove mounts before shutdown
            for (name, container) in self.applications.values().map(|a| (a.name(), &a.container)) {
                info!("Removing {}", name);
                crate::runtime::npk::uninstall(container)
                    .await
                    .map_err(Error::ProcessError)?;
            }

            self.events_tx.send(Event::Shutdown).await;
            Ok(())
        } else {
            let apps = self
                .applications
                .values()
                .filter_map(|app| app.process_context().map(|_| app.name().to_string()))
                .collect();
            Err(Error::ApplicationRunning(apps))
        }
    }

    // checks if the applicaion within the npk has an id (name) that is the same
    // as on of the already installed applications
    // returns the application id if it was installed, otherwise None
    async fn installed_application_id(&self, npk: &Path) -> Option<String> {
        extract_manifest(npk.into(), &self.signing_keys)
            .ok()
            .and_then(|manifest| {
                self.applications
                    .get(&manifest.name)
                    .map(|app| app.container.manifest.name.to_owned())
            })
    }

    /// Install a npk from give path
    pub async fn install(
        &mut self,
        npk: &Path,
        msg_id: MessageId,
        container_dir: Option<std::path::PathBuf>,
        tx: sync::Sender<Message>,
    ) {
        match extract_manifest(npk.into(), &self.signing_keys) {
            Err(e) => {
                warn!("Could not get package name from manifest");
                let _ = self
                    .events_tx
                    .send(Event::InstallationFinished(
                        e.into(),
                        std::path::PathBuf::from(npk),
                        msg_id,
                        tx,
                        None,
                    ))
                    .await;
            }
            Ok(manifest) => {
                let pkg_file_name = format!(
                    "{}-{}-{}.npk",
                    manifest.name,
                    manifest.platform.unwrap_or_else(|| "".to_string()),
                    manifest.version,
                );
                log::debug!(
                    "Try to install {}, checking the installed apps",
                    manifest.name
                );
                let registry_path = container_dir.map(|p| p.join(&pkg_file_name));
                if let Some(_installed_id) = self.installed_application_id(&npk).await {
                    warn!("Cannot install already installed application");
                    let _ = self
                        .events_tx
                        .send(Event::InstallationFinished(
                            InstallationResult::ApplicationAlreadyInstalled,
                            std::path::PathBuf::from(npk),
                            msg_id,
                            tx,
                            registry_path,
                        ))
                        .await;
                    return;
                }
                match npk::install(self, npk).await {
                    Ok(_) => {
                        info!("Installation succeeded!");
                        let _ = self
                            .events_tx
                            .send(Event::InstallationFinished(
                                InstallationResult::Success,
                                std::path::PathBuf::from(npk),
                                msg_id,
                                tx,
                                registry_path,
                            ))
                            .await;
                        // generate notification for installation event
                        self.notification_tx
                            .send(Notification::InstallationFinished(
                                self.installed_application_id(&npk)
                                    .await
                                    .unwrap_or(format!("{}", npk.to_string_lossy())),
                            ))
                            .await;
                    }
                    Err(e) => {
                        warn!("Installation failed");
                        let _ = self
                            .events_tx
                            .send(Event::InstallationFinished(
                                e.into(),
                                std::path::PathBuf::from(npk),
                                msg_id,
                                tx,
                                None,
                            ))
                            .await;
                    }
                }
            }
        }
    }

    fn is_app_installed(&self, name: &str, version: &Version) -> bool {
        match self.applications.get(name) {
            None => false,
            Some(app) => app.container.manifest.version == *version,
        }
    }

    /// Remove and umount a specific app
    /// app has to be stopped before it can be uninstalled
    pub async fn uninstall(&mut self, name: &str, version: &Version) -> result::Result<(), Error> {
        if !self.is_app_installed(name, version) {
            return Err(Error::ApplicationNotFound);
        }
        if let Some(app) = self.applications.get(name) {
            if app.is_running() {
                warn!("Cannot uninstall running container {}", app);
                return Err(Error::ApplicationRunning(vec![app.manifest().name.clone()]));
            }
            info!("Removing {}", app);
            npk::uninstall(app.container())
                .await
                .map_err(Error::UninstallationError)?;
            self.applications.remove(name);

            // remove npk from registry
            for d in &self.config.directories.container_dirs {
                let mut dir = fs::read_dir(&d)
                    .await
                    .map_err(|_| Error::UninstallationError(anyhow!("Could not read directory")))?;
                while let Some(res) = dir.next().await {
                    let entry = res.map_err(|_| {
                        Error::UninstallationError(anyhow!("Could not read directory"))
                    })?;
                    let manifest =
                        extract_manifest(entry.path().as_path().into(), &self.signing_keys)
                            .map_err(|_| {
                                Error::UninstallationError(anyhow!("Trouble with npk path"))
                            })?;

                    if manifest.name == name && manifest.version == *version {
                        fs::remove_file(&entry.path()).await.map_err(|_| {
                            Error::UninstallationError(anyhow!(
                                "Could not remove npk {}",
                                entry.path().to_string_lossy()
                            ))
                        })?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle the exit of a container. The restarting of containers is a subject
    /// to be removed and handled externally
    pub async fn on_exit(&mut self, name: &str, exit_status: &ExitStatus) -> Result<()> {
        if let Some(app) = self.applications.get_mut(name) {
            if let Some(context) = app.process.take() {
                info!(
                    "Process {} exited after {:?} and status {:?}",
                    app,
                    context.start_timestamp.elapsed(),
                    exit_status,
                );

                #[cfg(any(target_os = "android", target_os = "linux"))]
                {
                    let mut context = context;
                    if let Some(cgroups) = context.cgroups.take() {
                        log::debug!("Destroying cgroup configuration of {}", app);
                        cgroups.destroy().await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle out of memory conditions for container `name`
    pub async fn on_oom(&mut self, name: &str) -> result::Result<(), Error> {
        if let Some(app) = self.applications.get_mut(name) {
            if let Some(mut context) = app.process.take() {
                warn!("Process {} is out of memory. Stopping {}", app, app);
                // TODO: This might be under control of someone else. Maybe
                // add a flag to the manifest whether to stop a oom app
                // or not
                info!("Stopping {}", app);
                context
                    .process_mut()
                    .stop(Duration::from_secs(1))
                    .await
                    .map_err(Error::ProcessError)?;
                self.notification_tx
                    .send(Notification::OutOfMemory(name.to_owned()))
                    .await;
            }
        }
        Ok(())
    }
}
