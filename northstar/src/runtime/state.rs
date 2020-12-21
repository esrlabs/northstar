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
    mount::{mount_npk, mount_npk_repository, umount_npk},
    process::{ExitStatus, Process},
    Event, EventTx,
};
use crate::api::Notification;
use ed25519_dalek::*;
use log::{debug, info, warn};
use npk::{
    archive::{ArchiveReader, RepositoryId},
    manifest::{Manifest, Mount, Name, Version},
};
use std::{
    collections::{HashMap, HashSet},
    fmt, iter,
    path::{Path, PathBuf},
    result,
};
use tokio::{fs, stream::StreamExt, time};

#[derive(Debug, Clone)]
pub struct Repository {
    pub id: RepositoryId,
    pub dir: PathBuf,
    pub key: Option<PublicKey>,
}

#[derive(Debug)]
pub struct State {
    events_tx: EventTx,
    repositories: HashMap<RepositoryId, Repository>,
    pub applications: HashMap<Name, Application>,
    pub resources: HashMap<(Name, Version), Container>,
    pub config: Config,
}

#[derive(Debug)]
pub struct Container {
    pub manifest: Manifest,
    pub root: PathBuf,
    pub device: PathBuf,
    pub repository: RepositoryId,
}

impl Container {
    pub fn is_resource(&self) -> bool {
        self.manifest.init.is_none()
    }
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
        let mut repositories = HashMap::new();
        for (id, repository) in &config.repositories {
            let key = {
                if let Some(key) = repository.key.as_ref() {
                    Some(keys::load(&key).await.map_err(Error::Key)?)
                } else {
                    None
                }
            };
            let dir = repository.dir.clone();
            repositories.insert(
                id.clone(),
                Repository {
                    id: id.clone(),
                    dir,
                    key,
                },
            );
        }

        let mut state = State {
            events_tx: tx,
            repositories,
            applications: HashMap::new(),
            resources: HashMap::new(),
            config: config.clone(),
        };

        // mount all the containers from each repository
        mount_repositories(&mut state).await?;
        Ok(state)
    }

    /// Return an iterator over all known applications
    pub fn applications(&self) -> impl iter::Iterator<Item = &Application> {
        self.applications.values()
    }

    /// Return an iterator over all known resources
    pub fn resources(&self) -> impl iter::Iterator<Item = &Container> {
        self.resources.values()
    }

    /// Try to find a application with name `name`
    pub fn application(&self, name: &str) -> Option<&Application> {
        self.applications.get(name)
    }

    /// Return the list of repositories
    pub fn repositories(&self) -> &HashMap<RepositoryId, Repository> {
        &self.repositories
    }

    /// Add a container instance the list of known containers
    pub fn add(&mut self, container: Container) -> Result<(), Error> {
        let name = container.manifest.name.clone();
        let version = container.manifest.version.clone();
        if container.is_resource() {
            if self
                .resources
                .get(&(name.clone(), version.clone()))
                .is_some()
            {
                return Err(Error::ContainerAlreadyInstalled(name));
            }
            self.resources.insert((name, version), container);
        } else {
            if self.applications.get(&name).is_some() {
                return Err(Error::ContainerAlreadyInstalled(name));
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
            .map(|container| container.manifest.name.clone())
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
        if app.container.is_resource() {
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
            &self.config.run_dir,
            &self.config.data_dir,
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
            let wait_for_dm = self
                .repositories
                .get(&container.repository)
                .map(|r| r.key.is_some())
                .unwrap_or(false);
            umount_npk(container, wait_for_dm)
                .await
                .map_err(Error::Mount)?;
        }

        for container in self.resources() {
            let wait_for_dm = self
                .repositories
                .get(&container.repository)
                .map(|r| r.key.is_some())
                .unwrap_or(false);
            umount_npk(container, wait_for_dm)
                .await
                .map_err(Error::Mount)?;
        }

        Ok(())
    }

    /// Install a npk
    pub async fn install(&mut self, id: &str, npk: &Path) -> Result<(), Error> {
        let repository = self
            .repositories
            .get(id)
            .ok_or_else(|| Error::RepositoryNotFound(id.to_owned()))?;

        let manifest = ArchiveReader::new(npk, repository.key.as_ref())
            .map_err(Error::Npk)?
            .manifest()
            .clone();

        let package = format!("{}-{}.npk", manifest.name, manifest.version);
        debug!(
            "Trying to install {}. Checking the installed applications",
            manifest.name
        );

        let package_in_repository = repository.dir.join(&package);

        debug!(
            "Trying to install {} to repository {}",
            package,
            repository.dir.display()
        );

        if self
            .find_installed_npk(&manifest.name, &manifest.version)
            .await?
            .is_some()
        {
            warn!("Container with the same name and version already installed");
            return Err(Error::ContainerAlreadyInstalled(manifest.name.clone()));
        }

        // Copy tmp file into repository
        fs::copy(&npk, &package_in_repository)
            .await
            .map_err(|error| Error::Io("Failed to copy NPK to repository".to_string(), error))?;

        // Install and mount npk
        let mounted_container = mount_npk(&self.config, &package_in_repository, &repository)
            .await
            .map_err(Error::Mount)?;

        self.add(mounted_container)?;

        // Send notification about newly install npk
        Self::notification(
            &self.events_tx,
            Notification::Install(manifest.name.clone(), manifest.version.clone()),
        )
        .await;

        Ok(())
    }

    // finds the npk that contains either an application that matches the id
    // or a resource container that matches id and version
    async fn find_installed_npk(
        &self,
        name: &str,
        version: &Version,
    ) -> Result<Option<(Manifest, PathBuf)>, Error> {
        for repository in self.config.repositories.values() {
            let mut dir = fs::read_dir(&repository.dir).await.map_err(|e| {
                Error::Io(format!("Failed to read {}", repository.dir.display()), e)
            })?;
            while let Some(res) = dir.next().await {
                let entry = res.map_err(|e| {
                    Error::Io(
                        "Could not read directory".to_string(), // TODO: Which directory?
                        e,
                    )
                })?;

                let manifest = ArchiveReader::new(entry.path().as_path(), None)
                    .map_err(Error::Npk)?
                    .manifest()
                    .clone();

                if manifest.name == name && manifest.version == *version {
                    return Ok(Some((manifest, entry.path())));
                }
            }
        }
        Ok(None)
    }

    async fn uninstall_resource(
        &mut self,
        name: &str,
        version: &Version,
    ) -> result::Result<(), Error> {
        // check if resource still needed
        for app in self.applications() {
            for mount in app.container.manifest.mounts.values() {
                if let Mount::Resource {
                    name: res_name,
                    version: res_version,
                    ..
                } = mount
                {
                    if res_name == name && res_version == version {
                        info!(
                            "Cannot uninstall resource {}.{}, still needed by {}",
                            name,
                            version,
                            app.name()
                        );
                        return Err(Error::ResourceStillNeeded(format!("{}.{}", name, version)));
                    }
                }
            }
        }
        match self.resources.get(&(name.to_owned(), version.clone())) {
            Some(resource_container) => {
                let wait_for_dm = self
                    .repositories
                    .get(&resource_container.repository)
                    .map(|r| r.key.is_some())
                    .unwrap_or(false);
                umount_npk(resource_container, wait_for_dm)
                    .await
                    .map_err(Error::Mount)?;
                self.resources.remove(&(name.to_owned(), version.clone()));
                Ok(())
            }
            None => {
                log::warn!("Trying to uninstall resource container that is not installed");
                Err(Error::ApplicationNotFound)
            }
        }
    }

    async fn uninstall_app(&mut self, name: &str) -> result::Result<(), Error> {
        println!("try to uninstall {}", name);
        match self.applications.get(name) {
            Some(app) => {
                println!("we have {}", name);
                if app.is_running() {
                    println!("app was running");
                    Err(Error::ApplicationRunning(name.to_owned()))
                } else {
                    println!("unmounting");
                    let container = app.container();
                    let wait_for_dm = self
                        .repositories
                        .get(&container.repository)
                        .map(|r| r.key.is_some())
                        .unwrap_or(false);
                    umount_npk(container, wait_for_dm)
                        .await
                        .map_err(Error::Mount)?;
                    println!("unmounted");
                    self.applications.remove(name);
                    Ok(())
                }
            }
            None => Err(Error::ApplicationNotFound),
        }
    }
    /// Remove and umount a specific app
    /// app has to be stopped before it can be uninstalled
    pub async fn uninstall(&mut self, name: &str, version: &Version) -> result::Result<(), Error> {
        let uninstalled_path = match self.find_installed_npk(name, version).await? {
            None => {
                return Err(Error::ApplicationNotFound);
            }
            Some((manifest, npk_path)) => {
                if manifest.init.is_some() {
                    self.uninstall_app(name).await?;
                } else {
                    self.uninstall_resource(name, version).await?;
                }
                npk_path
            }
        };

        info!("Removing NPK {} from registry", uninstalled_path.display());
        fs::remove_file(&uninstalled_path).await.map_err(|e| {
            Error::Io(
                format!("Failed to remove {}", uninstalled_path.display()),
                e,
            )
        })?;

        Self::notification(
            &self.events_tx,
            Notification::Uninstalled(name.to_owned(), version.clone()),
        )
        .await;

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

async fn mount_repositories(state: &mut State) -> Result<(), Error> {
    let mut mounted_containers = Vec::new();

    // Mount all the containers from each repository
    for repo in state.repositories.values() {
        mounted_containers.append(
            &mut mount_npk_repository(&state.config, &repo)
                .await
                .map_err(Error::Mount)?,
        );
    }

    for container in mounted_containers {
        state.add(container)?;
    }

    Ok(())
}

// #[cfg(test)]
// mod tests {

//     use super::{Config, Container, State};
//     use anyhow::{Context, Result};
//     use npk::manifest::*;
//     use std::path::PathBuf;
//     use tokio::sync::mpsc;

//     #[tokio::test(flavor = "multi_thread")]
//     async fn uninstall_application() -> Result<()> {
//         let config_str = r#"
// debug = true
// console_address = "localhost:4200"
// container_uid = 1000
// container_gid = 1000

// [directories]
// container_dirs = [ "target/north/registry" ]
// run_dir = "target/north/run"
// data_dir = "target/north/data"
// key_dir = "../examples/keys"

// [cgroups]
// memory = "north"
// cpu = "north"

// [devices]
// unshare_root = "/"
// unshare_fstype = "ext4"
// loop_control = "/dev/loop-control"
// loop_dev = "/dev/loop"
// device_mapper = "/dev/mapper/control"
// device_mapper_dev = "/dev/dm-"
// "#;

//         let config: Config = toml::from_str(&config_str)
//             .with_context(|| format!("Failed to read configuration file {}", config_str))?;
//         let (event_tx, _event_rx) = mpsc::channel(1);
//         let mut state = State::new(&config, event_tx).await?;

//         use std::str::FromStr;
//         let test_manifest = r#"name: hello
// version: 0.0.2
// init: /hello
// env:
//     HELLO: north"#;
//         let manifest = Manifest::from_str(test_manifest)?;
//         let container = Container {
//             manifest,
//             root: PathBuf::from("test"),
//             device: PathBuf::from("test"),
//             repository: "repoA".to_owned(),
//         };

//         let name = container.manifest.name.clone();
//         state.add(container)?;
//         assert!(state.applications().last().is_some());
//         assert!(state.applications().last().is_some());
//         assert_eq!(1, state.applications().count());
//         assert_eq!(1, state.applications().count());
//         state.uninstall_app(&name).await?;
//         assert_eq!(0, state.applications().count());
//         Ok(())
//     }
// }
