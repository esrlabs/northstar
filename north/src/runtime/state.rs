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
    error::Error,
    keys,
    mount::{mount_npk, umount_npk},
    process::{ExitStatus, Process},
    Event, EventTx,
};
use crate::api::Notification;
use ed25519_dalek::*;
use log::{debug, info, warn};
use npk::{
    archive::{read_manifest, Container},
    manifest::{Manifest, Mount, Name, Version},
};
use std::{
    collections::{HashMap, HashSet},
    fmt, iter,
    path::Path,
    result,
};
use tokio::{fs, stream::StreamExt, time};

#[derive(Debug)]
pub struct State {
    events_tx: EventTx,
    pub signing_keys: HashMap<String, PublicKey>,
    pub applications: HashMap<Name, Application>,
    pub resources: HashMap<(Name, Version), Application>,
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
    cgroups: Option<super::cgroups::CGroups>,
}

impl ProcessContext {
    pub fn process(&self) -> &dyn Process {
        self.process.as_ref()
    }

    pub fn process_mut(&mut self) -> &mut dyn Process {
        self.process.as_mut()
    }

    pub fn uptime(&self) -> time::Duration {
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
    pub(super) async fn new(config: &Config, tx: EventTx) -> Result<State, Error> {
        // Load keys for manifest verification
        let signing_keys = keys::load(&config.directories.key_dir)
            .await
            .map_err(Error::Key)?;

        Ok(State {
            events_tx: tx,
            signing_keys,
            applications: HashMap::new(),
            resources: HashMap::new(),
            config: config.clone(),
        })
    }

    /// Return an iterator over all known applications
    pub fn applications(&self) -> impl iter::Iterator<Item = &Application> {
        self.applications.values()
    }

    /// Return an iterator over all known resources
    pub fn resources(&self) -> impl iter::Iterator<Item = &Application> {
        self.resources.values()
    }

    /// Try to find a application with name `name`
    pub fn application(&mut self, name: &str) -> Option<&Application> {
        self.applications.get(name)
    }

    /// Add a container instance the list of known containers
    pub fn add(&mut self, container: Container) -> Result<(), Error> {
        let name = container.manifest.name.clone();
        let version = container.manifest.version.clone();
        if container.is_resource_container() {
            if self
                .resources
                .get(&(name.clone(), version.clone()))
                .is_some()
            {
                return Err(Error::ApplicationAlreadyInstalled(name));
            }
            let app = Application::new(container);
            self.resources.insert((name, version), app);
        } else {
            if self.applications.get(&name).is_some() {
                return Err(Error::ApplicationAlreadyInstalled(name));
            }
            let app = Application::new(container);
            self.applications.insert(name, app);
        }
        Ok(())
    }

    pub async fn start(&mut self, name: &str) -> result::Result<(), Error> {
        // Setup set of available resources
        let resources = self
            .resources
            .values()
            .map(|app| app.container.manifest.name.clone())
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
            return Err(Error::ApplicationRunning(app.manifest().name.clone()));
        }

        // Check if app is a resource container that cannot be started
        if app.container.is_resource_container() {
            warn!("Cannot start resource containers ({})", app);
            return Err(Error::ApplicationNotFound);
        }

        // Check for all required resources
        for mount in app.container.manifest.mounts.values() {
            if let Mount::Resource { name, .. } = mount {
                if !resources.contains(name) {
                    return Err(Error::MissingResource(name.clone()));
                }
            }
        }

        // Spawn process
        info!("Starting {}", app);

        let process = super::minijail::Process::start(
            &app.container,
            self.events_tx.clone(),
            &self.config.directories.run_dir,
            &self.config.directories.data_dir,
            self.config.container_uid,
            self.config.container_gid,
        )
        .await
        .map_err(Error::Process)?;

        let process = Box::new(process) as Box<dyn Process>;

        // CGroups
        let cgroups = if let Some(ref c) = app.manifest().cgroups {
            debug!("Creating cgroup configuration for {}", app);
            let cgroups = super::cgroups::CGroups::new(
                &self.config.cgroups,
                app.name(),
                c,
                self.events_tx.clone(),
            )
            .await
            .map_err(Error::Cgroups)?;

            debug!("Assigning {} to cgroup {}", process.pid(), app);
            cgroups
                .assign(process.pid())
                .await
                .map_err(Error::Cgroups)?;
            Some(cgroups)
        } else {
            None
        };

        app.process = Some(ProcessContext {
            process,
            incarnation: 0,
            start_timestamp: time::Instant::now(),
            cgroups,
        });

        Self::notification(
            &self.events_tx,
            Notification::ApplicationStarted(
                name.to_owned(),
                app.container.manifest.version.clone(),
            ),
        )
        .await;

        info!("Started {}", app);

        Ok(())
    }

    /// Stop a application. Timeout specifies the time until the process is
    /// SIGKILLed if it doesn't exit when receiving a SIGTERM
    pub async fn stop(&mut self, name: &str, timeout: time::Duration) -> result::Result<(), Error> {
        if let Some(app) = self.applications.get_mut(name) {
            if let Some(mut context) = app.process.take() {
                info!("Stopping {}", app);
                let status = context
                    .process
                    .stop(timeout)
                    .await
                    .map_err(Error::Process)?;

                if let Some(cgroups) = context.cgroups {
                    debug!("Destroying cgroup configuration of {}", app);
                    cgroups.destroy().await.map_err(Error::Cgroups)?;
                }

                // Send notification to main loop
                Self::notification(
                    &self.events_tx,
                    Notification::ApplicationStopped(
                        name.to_owned(),
                        app.container.manifest.version.clone(),
                    ),
                )
                .await;

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

    /// Send a shutdown request to the main loop
    pub async fn initiate_shutdown(&mut self) {
        self.events_tx
            .send(Event::Shutdown)
            .await
            .expect("Internal channel error on main");
    }

    /// Shutdown the runtime: stop running applications and umount npks
    pub async fn shutdown(&mut self) -> result::Result<(), Error> {
        let running_containers: Vec<String> = self
            .applications
            .values()
            .filter_map(|a| a.process.as_ref().and(Some(a.name().clone())))
            .collect();
        for name in running_containers {
            self.stop(&name, time::Duration::from_secs(5)).await?;
        }

        for (_name, container) in self.applications.values().map(|a| (a.name(), &a.container)) {
            umount_npk(container).await.map_err(Error::Mount)?;
        }

        for (name, container) in self.resources().map(|a| (a.name(), &a.container)) {
            info!("Umounting {}", name);
            umount_npk(container).await.map_err(Error::Mount)?;
        }

        Ok(())
    }

    /// Install a npk
    pub async fn install(&mut self, npk: &Path) -> Result<(), Error> {
        let manifest = read_manifest(npk, &self.signing_keys).map_err(Error::Npk)?;

        let package = format!("{}-{}.npk", manifest.name, manifest.version);
        debug!(
            "Trying to install {}. Checking the installed applications",
            manifest.name
        );

        // TODO: get correct registry from config
        let registry = self
            .config
            .directories
            .container_dirs
            .first()
            .expect("No registry configured!");

        let package_in_registry = registry.join(&package);

        debug!(
            "Trying to install {} to registry {}",
            package,
            registry.display()
        );

        if manifest.init.is_none() {
            if self
                .resources
                .contains_key(&(manifest.name.clone(), manifest.version.clone()))
            {
                warn!("Resource container with same version already installed");
                return Err(Error::ResourceAlreadyInstalled(manifest.name.clone()));
            }
        } else if self.applications.contains_key(&manifest.name) {
            return Err(Error::ApplicationAlreadyInstalled(manifest.name.clone()));
        }

        // Copy tmpfile into registry
        fs::copy(&npk, &package_in_registry)
            .await
            .map_err(|error| Error::Io("Failed to copy npk to registry".to_string(), error))?;

        // Install and mount npk
        let mounted_containers = mount_npk(
            &self.config.directories.run_dir,
            &self.signing_keys,
            &self.config.devices.device_mapper_dev,
            &self.config.devices.device_mapper,
            &self.config.devices.loop_control,
            &self.config.devices.loop_dev,
            &package_in_registry,
        )
        .await
        .map_err(Error::Mount)?;

        for container in mounted_containers {
            self.add(container)?;
        }

        // Remove tmpfile
        // TODO: move this to console?
        fs::remove_file(npk)
            .await
            .map_err(|error| Error::Io(format!("Failed to remove {}", npk.display()), error))?;

        // Send notification about newly install npk
        Self::notification(
            &self.events_tx,
            Notification::Install(manifest.name.clone(), manifest.version.clone()),
        )
        .await;

        Ok(())
    }

    fn is_installed(&self, name: &str, version: &Version) -> bool {
        match self.applications.get(name) {
            None => self
                .resources
                .get(&(name.to_string(), version.clone())) // TODO get rid of copy
                .is_some(),
            Some(app) => app.container.manifest.version == *version,
        }
    }

    /// Remove and umount a specific app
    /// app has to be stopped before it can be uninstalled
    pub async fn uninstall(&mut self, name: &str, version: &Version) -> result::Result<(), Error> {
        if !self.is_installed(name, version) {
            return Err(Error::ApplicationNotFound);
        }

        let installed_app = self.applications.get(name);
        let to_uninstall = match installed_app {
            Some(app) => {
                if app.is_running() {
                    warn!("Cannot uninstall started container {}", app);
                    return Err(Error::ApplicationRunning(app.manifest().name.clone()));
                }
                Some(app)
            }
            None => self.resources.get(&(name.to_string(), version.clone())),
        };
        if let Some(app) = to_uninstall {
            if app.is_running() {
                warn!("Cannot uninstall started container {}", app);
                return Err(Error::ApplicationRunning(app.manifest().name.clone()));
            }
            info!("Uninstalling {}", app);
            umount_npk(app.container()).await.map_err(Error::Mount)?;
            self.applications.remove(name);
            self.resources.remove(&(name.to_string(), version.clone()));

            // Remove npk from registry
            for d in &self.config.directories.container_dirs {
                let mut dir = fs::read_dir(&d)
                    .await
                    .map_err(|e| Error::Io(format!("Failed to read {}", d.display()), e))?;
                while let Some(res) = dir.next().await {
                    let entry = res.map_err(|e| {
                        Error::Io(
                            "Could not read directory".to_string(), // TODO: Which directory?
                            e,
                        )
                    })?;
                    let manifest = read_manifest(entry.path().as_path(), &self.signing_keys)
                        .map_err(Error::Npk)?;

                    if manifest.name == name && manifest.version == *version {
                        fs::remove_file(&entry.path()).await.map_err(|e| {
                            Error::Io(format!("Failed to remove {}", entry.path().display()), e)
                        })?;
                    }
                }
            }

            Self::notification(
                &self.events_tx,
                Notification::Uninstalled(name.to_owned(), version.clone()),
            )
            .await;
        }

        Ok(())
    }

    /// Handle the exit of a container. The restarting of containers is a subject
    /// to be removed and handled externally
    pub async fn on_exit(&mut self, name: &str, exit_status: &ExitStatus) -> Result<(), Error> {
        if let Some(app) = self.applications.get_mut(name) {
            if let Some(context) = app.process.take() {
                info!(
                    "Process {} exited after {:?} and status {:?}",
                    app,
                    context.start_timestamp.elapsed(),
                    exit_status,
                );

                let mut context = context;
                if let Some(cgroups) = context.cgroups.take() {
                    debug!("Destroying cgroup configuration of {}", app);
                    cgroups.destroy().await.map_err(Error::Cgroups)?;
                }

                let exit_info = match exit_status {
                    ExitStatus::Exit(c) => format!("Exited with code {}", c),
                    ExitStatus::Signaled(s) => format!("Terminated by signal {}", s.as_str()),
                };

                Self::notification(
                    &self.events_tx,
                    Notification::ApplicationExited {
                        id: name.to_owned(),
                        version: app.container.manifest.version.clone(),
                        exit_info,
                    },
                )
                .await;
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
                    .stop(time::Duration::from_secs(1))
                    .await
                    .map_err(Error::Process)?;

                self.events_tx
                    .send(Event::Notification(Notification::OutOfMemory(
                        name.to_owned(),
                    )))
                    .await
                    .expect("Internal channel error on main");
            }
        }
        Ok(())
    }

    async fn notification(tx: &EventTx, n: Notification) {
        tx.send(Event::Notification(n))
            .await
            .expect("Internal channel error on main");
    }
}
