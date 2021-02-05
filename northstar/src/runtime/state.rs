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
    minijail::{Minijail, Process},
    mount::MountControl,
    process::ExitStatus,
    Event, EventTx, RepositoryId,
};
use crate::api::model::Notification;
use ed25519_dalek::*;
use log::{debug, info, warn};
use npk::{
    manifest::{Manifest, Mount, Name, Version},
    npk::Npk,
};
use std::{
    collections::{HashMap, HashSet},
    fmt, iter,
    path::{Path, PathBuf},
    result,
};
use tokio::{fs, time};

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
    applications: HashMap<Name, Application>,
    resources: HashMap<(Name, Version), Container>,
    config: Config,
    minijail: Minijail,
    mount_control: MountControl,
    /// Internal test repository tempdir
    #[cfg(debug_assertions)]
    internal_repository: tempfile::TempDir,
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
    process: Process,
    incarnation: u32,
    start_timestamp: time::Instant,
    cgroups: Option<super::cgroups::CGroups>,
}

impl ProcessContext {
    pub(crate) fn process(&self) -> &Process {
        &self.process
    }

    pub(crate) fn process_mut(&mut self) -> &mut Process {
        &mut self.process
    }

    pub(crate) fn uptime(&self) -> time::Duration {
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

/// Dump the hello world npk created at compile time into a tmpdir that acts as internal
/// repository.
#[cfg(debug_assertions)]
async fn prepare_hello_world_repo(name: &str) -> Result<(tempfile::TempDir, Repository), Error> {
    let hello_world = include_bytes!(concat!(env!("OUT_DIR"), "/hello_world-0.0.1.npk"));
    let tempdir = tokio::task::block_in_place(|| {
        tempfile::tempdir().map_err(|e| Error::Io("Failed to create tmpdir".into(), e))
    })?;
    let dir = tempdir.path().to_owned();
    let npk = dir.join("hello_world-0.0.1.npk");

    fs::write(&npk, hello_world)
        .await
        .map_err(|e| Error::Io(format!("Failed to write {}", npk.display()), e))
        .map(|_| {
            (
                tempdir,
                Repository {
                    id: name.to_owned(),
                    dir,
                    key: None,
                },
            )
        })
}

impl State {
    /// Create a new empty State instance
    pub(super) async fn new(config: &Config, tx: EventTx) -> Result<State, Error> {
        let mut repositories = HashMap::new();

        // Internal test repository
        #[cfg(debug_assertions)]
        let internal_repository = {
            let name = "internal".to_string();
            let (dir, repository) = prepare_hello_world_repo(&name).await?;
            repositories.insert(name, repository);
            dir
        };

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

        let minijail =
            Minijail::new(tx.clone(), &config.run_dir, &config.data_dir).map_err(Error::Process)?;

        let mut state = State {
            events_tx: tx,
            repositories,
            applications: HashMap::new(),
            resources: HashMap::new(),
            config: config.clone(),
            minijail,
            mount_control: MountControl::new(&config).await.map_err(Error::Mount)?,
            #[cfg(debug_assertions)]
            internal_repository,
        };

        // Mount all the containers from each repository
        state.mount_repositories().await?;
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

        let process = self
            .minijail
            .start(&app.container)
            .await
            .map_err(Error::Process)?;

        // CGroups
        let cgroups = if let Some(ref c) = app.manifest().cgroups {
            debug!("Configuring CGroups of {}", app);
            let cgroups = super::cgroups::CGroups::new(
                &self.config.cgroups,
                app.name(),
                c,
                self.events_tx.clone(),
            )
            .await
            .map_err(Error::Cgroups)?;

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
                    .terminate(timeout)
                    .await
                    .map_err(Error::Process)?;

                if let Some(cgroups) = context.cgroups {
                    debug!("Destroying cgroup configuration of {}", app);
                    cgroups.destroy().await?;
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
            self.mount_control
                .umount_npk(container, wait_for_dm)
                .await
                .map_err(Error::Mount)?;
        }

        for container in self.resources() {
            let wait_for_dm = self
                .repositories
                .get(&container.repository)
                .map(|r| r.key.is_some())
                .unwrap_or(false);
            self.mount_control
                .umount_npk(container, wait_for_dm)
                .await
                .map_err(Error::Mount)?;
        }

        self.minijail.shutdown().map_err(Error::Process)
    }

    /// Install an NPK
    pub async fn install(&mut self, id: &str, npk: &Path) -> Result<(), Error> {
        let repository = self.repositories.get(id).ok_or_else(|| {
            Error::RepositoryIdUnknown(
                id.to_owned(),
                self.repositories.keys().map(|id| id.into()).collect(),
            )
        })?;

        let manifest = Npk::from_path(&npk, repository.key.as_ref())
            .await
            .map_err(Error::Npk)
            .map(|npk| npk.manifest().clone())?;

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
        // Check if required resources exist
        let required_resources = manifest.mounts.values().filter_map(|m| match m {
            Mount::Resource { name, version, .. } => Some((name, version)),
            _ => None,
        });

        for (name, version) in required_resources {
            if let Ok(false) = self.resource_available(name, version).await {
                return Err(Error::MissingResource(format!(
                    "Resource {}.{} unavailable",
                    name, version
                )));
            }
        }

        // Copy tmp file into repository
        fs::copy(&npk, &package_in_repository)
            .await
            .map_err(|error| Error::Io("Failed to copy NPK to repository".to_string(), error))?;

        // Install and mount npk
        let mounted_container = self
            .mount_control
            .mount_npk(&package_in_repository, &repository, &self.config.run_dir)
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

    async fn resource_available(&self, name: &str, version: &Version) -> Result<bool, Error> {
        Ok(self.find_installed_npk(name, version).await?.is_some())
    }

    // Finds the npk that contains either an application that matches the id
    // or a resource container that matches id and version
    async fn find_installed_npk(
        &self,
        name: &str,
        version: &Version,
    ) -> Result<Option<(Manifest, PathBuf)>, Error> {
        for (id, repository) in &self.config.repositories {
            let mut dir = fs::read_dir(&repository.dir).await.map_err(|e| {
                Error::Io(format!("Failed to read {}", repository.dir.display()), e)
            })?;
            while let Ok(Some(entry)) = dir.next_entry().await {
                let manifest = Npk::from_path(
                    entry.path().as_path(),
                    self.repositories.get(id).unwrap().key.as_ref(),
                )
                .await
                .map_err(Error::Npk)
                .map(|n| n.manifest().clone())?;

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
        // Check if resource still needed
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
                        return Err(Error::ResourceBusy(format!(
                            "{}.{} needed by {}",
                            name,
                            version,
                            app.name()
                        )));
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
                self.mount_control
                    .umount_npk(resource_container, wait_for_dm)
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
        match self.applications.get(name) {
            Some(app) => {
                if app.is_running() {
                    Err(Error::ApplicationRunning(name.to_owned()))
                } else {
                    let container = app.container();
                    let wait_for_dm = self
                        .repositories
                        .get(&container.repository)
                        .map(|r| r.key.is_some())
                        .unwrap_or(false);
                    self.mount_control
                        .umount_npk(container, wait_for_dm)
                        .await
                        .map_err(Error::Mount)?;
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
            Some((manifest, npk)) => {
                if manifest.init.is_some() {
                    self.uninstall_app(name).await?;
                } else {
                    self.uninstall_resource(name, version).await?;
                }
                npk
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
            if let Some(mut context) = app.process.take() {
                info!(
                    "Process {} exited after {:?} and status {:?}",
                    app,
                    context.start_timestamp.elapsed(),
                    exit_status,
                );

                if let Some(cgroups) = context.cgroups.take() {
                    debug!("Destroying cgroup configuration of {}", app);
                    cgroups.destroy().await?;
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
                    .terminate(time::Duration::from_secs(1))
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

    /// Mount all the containers in every repository
    async fn mount_repositories(&mut self) -> Result<(), Error> {
        let mut mounted_containers = Vec::new();

        // Mount all the containers from each repository
        for repo in self.repositories.keys() {
            let mut containers = self.mount_repository(&repo).await?;
            mounted_containers.append(&mut containers);
        }

        for container in mounted_containers {
            self.add(container)?;
        }

        Ok(())
    }

    /// Mounts all the `npk` files in the specified repository
    async fn mount_repository(&self, repo_id: &str) -> Result<Vec<Container>, Error> {
        let repo = self.repositories.get(repo_id).ok_or_else(|| {
            Error::RepositoryIdUnknown(
                repo_id.to_string(),
                self.repositories().keys().map(|id| id.into()).collect(),
            )
        })?;

        info!("Mounting NPKs from {}", repo.dir.display());
        let mut dir = fs::read_dir(&repo.dir).await.map_err(|e| {
            Error::Io(
                format!(
                    "Failed to read repository at {}",
                    &repo.dir.to_string_lossy()
                ),
                e,
            )
        })?;
        let mut containers = Vec::new();

        while let Ok(Some(entry)) = dir.next_entry().await {
            let container = self
                .mount_control
                .mount_npk(&entry.path(), repo, &self.config.run_dir)
                .await
                .map_err(Error::Mount)?;
            containers.push(container);
        }

        Ok(containers)
    }
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
