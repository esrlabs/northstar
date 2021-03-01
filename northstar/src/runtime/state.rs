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

use crate::api;

use super::{
    config::Config,
    console::Request,
    error::Error,
    key,
    minijail::{Minijail, Process},
    mount::MountControl,
    ContainerKey, Event, EventTx, ExitStatus, Notification, Repository, RepositoryId,
};
use api::model::Response;
use log::{debug, error, info, warn};
use npk::{
    manifest::{Manifest, Mount},
    npk::Npk,
};
use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    result,
};
use tokio::{sync::oneshot, time};

#[derive(Debug)]
pub(super) struct State<'a> {
    config: &'a Config,
    minijail: Minijail<'a>,
    mount_control: MountControl,
    events_tx: EventTx,
    repositories: HashMap<RepositoryId, Repository>,
    npks: HashMap<ContainerKey, PathBuf>,
    containers: HashMap<ContainerKey, Container>,
    /// Internal test repository tempdir
    #[cfg(debug_assertions)]
    internal_repository: tempfile::TempDir,
}

#[derive(Debug)]
pub enum BlockDevice {
    Loopback(PathBuf),
    Verity(PathBuf),
}

#[derive(Debug)]
pub(super) struct Container {
    pub(super) manifest: Manifest,
    pub(super) root: PathBuf,
    pub(super) device: BlockDevice,
    pub(super) process: Option<ProcessContext>,
}

impl fmt::Display for Container {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.manifest.name, self.manifest.version)
    }
}

#[derive(Debug)]
pub(super) struct ProcessContext {
    started: time::Instant,
    process: Process,
    cgroups: Option<super::cgroups::CGroups>,
}

impl ProcessContext {
    async fn destroy(mut self) -> Result<(), Error> {
        if let Some(cgroups) = self.cgroups.take() {
            cgroups.destroy().await?;
        }

        self.process.destroy().await.map_err(Error::Process)?;
        Ok(())
    }
}

impl<'a> State<'a> {
    /// Create a new empty State instance
    pub(super) async fn new(config: &'a Config, events_tx: EventTx) -> Result<State<'a>, Error> {
        let mut repositories = HashMap::new();

        // Internal test repository
        #[cfg(debug_assertions)]
        let internal_repository = {
            let name = "internal".to_string();
            let (dir, repository) = prepare_internal_repository(&name).await?;
            repositories.insert(name, repository);
            dir
        };

        // Build a map of repositories from the configuration
        for (id, repository) in &config.repositories {
            let key = {
                if let Some(key) = repository.key.as_ref() {
                    Some(key::load(&key).await.map_err(Error::Key)?)
                } else {
                    None
                }
            };
            let dir = repository.dir.clone();
            repositories.insert(id.clone(), Repository::new(id.clone(), dir, key).await?);
        }

        // Build a list of npks from the repositories
        let mut npks = HashMap::new();
        for (id, repository) in &repositories {
            for ((name, version), npk) in repository.npks() {
                let key = ContainerKey::new(name.clone(), version.clone(), id.clone());
                npks.insert(key, npk.clone());
            }
        }

        let minijail = Minijail::new(events_tx.clone(), config).await.map_err(Error::Process)?;
        let mount_control = MountControl::new(&config).await.map_err(Error::Mount)?;

        Ok(State {
            events_tx,
            repositories,
            npks,
            containers: HashMap::new(),
            config,
            minijail,
            mount_control,
            #[cfg(debug_assertions)]
            internal_repository,
        })
    }

    /// Mount `key`
    async fn mount(&self, key: &ContainerKey) -> Result<Container, Error> {
        // Repository key
        let repository_key = self
            .repositories
            .get(key.repository())
            .and_then(|r| r.key.as_ref());
        let npk = self
            .npks
            .get(&key)
            .ok_or_else(|| Error::UnknownApplication(key.clone()))?;

        // Load NPK
        let npk = Npk::from_path(npk, repository_key)
            .await
            .map_err(Error::Npk)?;
        let manifest = npk.manifest().clone();

        // Try to mount the npk found. If this fails return with an error - nothing needs to
        // be cleaned up.
        let root = self.config.run_dir.join(key.to_string());
        let device = self
            .mount_control
            .mount(npk, &root, repository_key)
            .await
            .map_err(Error::Mount)
            .map(|device| {
                if repository_key.is_some() {
                    BlockDevice::Verity(device)
                } else {
                    BlockDevice::Loopback(device)
                }
            })?;

        Ok(Container {
            manifest,
            root,
            device,
            process: None,
        })
    }

    /// Umount a given container key
    #[allow(clippy::blocks_in_if_conditions)]
    async fn umount(&mut self, key: &ContainerKey) -> Result<Container, Error> {
        if let Some(container) = self.containers.get(key) {
            info!("Umounting {}", key);
            // Check if the application is started - if yes it cannot be uninstalled
            if container.process.is_some() {
                return Err(Error::ApplicationStarted(key.clone()));
            }

            // If this is a resource check if it can be uninstalled or if it's
            // used by any (mounted) container. The not mounted containers are
            // not interesting because the check for all resources is done when
            // it's mounted/started.
            if container.manifest.init.is_none()
                && self
                    .containers
                    .values()
                    .filter(|c| c.process.is_some()) // Just started containers count
                    .map(|c| &c.manifest.mounts)
                    .flatten() // A iter of Mounts
                    .map(|(_, mount)| mount)
                    .filter_map(|mount| match mount {
                        Mount::Resource {
                            name,
                            version,
                            repository,
                            ..
                        } => Some((name, version, repository)),
                        _ => None,
                    })
                    .any(|(name, version, repository)| {
                        name == key.name()
                            && version == key.version()
                            && repository == key.repository()
                    })
            {
                warn!("Failed to uninstall busy resource container {}", key);
                return Err(Error::ResourceBusy);
            }

            let skey = self
                .repositories
                .get(key.repository())
                .and_then(|r| r.key.as_ref());
            let device = skey.map(|_| &container.device).and_then(|p| match p {
                BlockDevice::Loopback(_) => None,
                BlockDevice::Verity(p) => Some(p.as_path()),
            });

            self.mount_control
                .umount(&container.root, device)
                .await
                .expect("Failed to umount");
            Ok(self.containers.remove(key).expect("Internal error"))
        } else {
            panic!("Container {} is not mounted", key)
        }
    }

    pub(super) async fn start(&mut self, key: &ContainerKey) -> Result<(), Error> {
        info!("Trying to start {}", key);

        let mut mounted = Vec::new();

        let manifest = if let Some(container) = self.containers.get(key) {
            // Check if the container is not a resouce
            if container.manifest.init.is_none() {
                warn!("Container {} is a resource", key);
                return Err(Error::UnknownApplication(key.clone()));
            }

            // Check if the container is already started
            if container.process.is_some() {
                warn!("Application {} is already running", key);
                return Err(Error::ApplicationStarted(key.clone()));
            }

            container.manifest.clone()
        } else if self.npks.contains_key(key) {
            let container = self.mount(&key).await?;
            let manifest = container.manifest.clone();
            mounted.push(key.clone());
            self.containers.insert(key.clone(), container);
            manifest
        } else {
            warn!("Unknown application {}", key);
            return Err(Error::UnknownApplication(key.clone()));
        };

        // Find to be mounted resources
        for key in manifest.mounts.values().filter_map(|m| match m {
            Mount::Resource {
                name,
                version,
                repository,
                ..
            } => Some(ContainerKey::new(
                name.clone(),
                version.clone(),
                repository.clone(),
            )),
            _ => None,
        }) {
            // Mount not yet mounted resources
            if !self.containers.contains_key(&key) {
                if self.npks.contains_key(&key) {
                    // Obtain the key from the repo - needed for mounting
                    match self.mount(&key).await {
                        Ok(container) => {
                            // Fine. Add the container to the list of mounted containers
                            mounted.push(key.clone());
                            self.containers.insert(key, container);
                        }
                        Err(e) => {
                            warn!("Failed to mount {}", key);
                            // Umount everything mounted for this particular start operation
                            for k in mounted.drain(..) {
                                self.umount(&k).await.ok();
                            }
                            return Err(e);
                        }
                    }
                } else {
                    for k in mounted.drain(..) {
                        self.umount(&k).await.ok();
                    }
                    return Err(Error::UnknownResource(key));
                }
            }
        }

        // This must exist
        let container = self.containers.get(key).unwrap();

        // Spawn process
        info!("Creating {}", key);
        let mut process = match self
            .minijail
            .create(&key, &container)
            .await
            .map_err(Error::Process)
        {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to create process for {}", key);
                // Umount everything mounted so far for this start command
                for k in mounted.drain(..) {
                    self.umount(&k).await.ok();
                }
                warn!("Failed to start {}", key);
                return Err(e);
            }
        };

        // CGroups
        let cgroups = if let Some(ref c) = container.manifest.cgroups {
            debug!("Configuring CGroups of {}", key);
            let cgroups =
                // Creating a cgroup is a northstar internal thing. If it fails it's not recoverable.
                super::cgroups::CGroups::new(&self.config.cgroups, &key, c, self.events_tx.clone())
                    .await
                    .map_err(Error::Cgroups).expect("Failed to create cgroup");

            // Assigning a pid to a cgroup created by us must work otherwise we did something wrong.
            cgroups
                .assign(process.pid())
                .await
                .map_err(Error::Cgroups)
                .expect("Failed to assign PID to cgroups");
            Some(cgroups)
        } else {
            None
        };

        // Signal the process to continue starting. This can fail because of the container
        // content. In case umount everything mounted so far and return the error.
        if let Err(e) = process.start().await.map_err(Error::Process) {
            warn!("Failed to resume process of {}", key);
            for key in mounted.drain(..) {
                self.umount(&key).await.ok();
            }
            warn!("Failed to start {}", key);
            return Err(e);
        }

        let container = self.containers.get_mut(&key).unwrap();

        // Add process context to process
        container.process = Some(ProcessContext {
            process,
            started: time::Instant::now(),
            cgroups,
        });

        info!("Started {}", key);

        self.notification(Notification::Started(key.clone())).await;

        Ok(())
    }

    /// Stop a application. Timeout specifies the time until the process is
    /// SIGKILLed if it doesn't exit when receiving a SIGTERM
    pub(super) async fn stop(
        &mut self,
        key: &ContainerKey,
        timeout: time::Duration,
    ) -> Result<(), Error> {
        if let Some(mut context) = self.containers.get_mut(&key).and_then(|c| c.process.take()) {
            info!("Stopping {}", key);
            let status = context
                .process
                .terminate(timeout)
                .await
                .map_err(Error::Process)
                .expect("Failed to terminate process");

            context.destroy().await.expect("Failed to destroy context");

            // Send notification to main loop
            self.notification(Notification::Stopped(key.clone())).await;

            info!("Stopped {} with status {}", key, status);

            Ok(())
        } else {
            Err(Error::UnknownApplication(key.clone()))
        }
    }

    /// Shutdown the runtime: stop running applications and umount npks
    pub(super) async fn shutdown(mut self) -> Result<(), Error> {
        // Stop started containers
        let started = self
            .containers
            .iter()
            .filter_map(|(key, container)| container.process.as_ref().map(|_| key))
            .cloned()
            .collect::<Vec<_>>();
        // Stop started applications
        for key in &started {
            self.stop(&key, time::Duration::from_secs(5)).await?;
        }

        let keys = self.containers.keys().cloned().collect::<Vec<_>>();
        for key in &keys {
            self.umount(key).await?;
        }

        self.minijail.shutdown().await.map_err(Error::Process)
    }

    /// Install an NPK
    async fn install(&mut self, repository_id: &str, src: &Path) -> Result<(), Error> {
        debug!("Trying to install {}", src.display());
        let repository = self
            .repositories
            .get_mut(repository_id)
            .ok_or_else(|| Error::UnknownRepository(repository_id.to_string()))?;
        let npk = Npk::from_path(src, repository.key.as_ref())
            .await
            .map_err(Error::Npk)?;
        let manifest = npk.manifest();
        let key = ContainerKey::new(
            manifest.name.clone(),
            manifest.version.clone(),
            repository_id.to_string(),
        );

        debug!("NPK key is {}", key);

        // Add the npk to the repository
        repository.add(&key, src).await?;

        // Add the npk into the list of known npks
        self.npks.insert(key.clone(), src.into());

        // TODO: Optimize this
        for (id, repository) in &self.repositories {
            for ((name, version), npk) in repository.npks() {
                let key = ContainerKey::new(name.clone(), version.clone(), id.clone());
                self.npks.insert(key, npk.clone());
            }
        }

        debug!("Successfully installed {}", key);

        Ok(())
    }

    /// Remove and umount a specific app
    #[allow(clippy::blocks_in_if_conditions)]
    async fn uninstall(&mut self, key: &ContainerKey) -> result::Result<(), Error> {
        debug!("Trying to uninstall {}", key);

        if !self.npks.contains_key(key) {
            warn!("Failed to uninstall unknown container {}", key);
            return Err(Error::UnknownApplication(key.clone()));
        }

        if self.containers.contains_key(key) {
            self.umount(key).await?;
        }

        let repository = self
            .repositories
            .get_mut(key.repository())
            .ok_or_else(|| Error::UnknownRepository(key.repository().clone()))?;

        repository.remove(key).await?;
        self.npks.remove(key);

        debug!("Successfully uninstalled {}", key);

        Ok(())
    }

    /// Handle the exit of a container. The restarting of containers is a subject
    /// to be removed and handled externally
    pub(super) async fn on_exit(
        &mut self,
        key: &ContainerKey,
        status: &ExitStatus,
    ) -> Result<(), Error> {
        if let Some(container) = self.containers.get_mut(&key) {
            if let Some(context) = container.process.take() {
                info!(
                    "Process {} exited after {:?} with status {:?}",
                    container,
                    context.started.elapsed(),
                    status,
                );

                context.destroy().await.expect("Failed to destroy context");

                self.notification(Notification::Exit {
                    key: key.clone(),
                    status: status.clone(),
                })
                .await;
            }
        }
        Ok(())
    }

    /// Handle out of memory conditions for container `name`
    pub(super) async fn on_oom(&mut self, key: &ContainerKey) -> Result<(), Error> {
        if self
            .containers
            .get(key)
            .and_then(|c| c.process.as_ref())
            .is_some()
        {
            warn!("Process {} is out of memory. Stopping", key);
            self.notification(Notification::OutOfMemory(key.clone()))
                .await;
            self.stop(key, time::Duration::from_secs(5)).await?;
        }
        Ok(())
    }

    /// Process console events
    pub(super) async fn console_request(
        &mut self,
        request: &Request,
        response_tx: oneshot::Sender<api::model::Response>,
    ) -> Result<(), Error> {
        match request {
            Request::Message(message) => {
                let payload = &message.payload;
                if let api::model::Payload::Request(ref request) = payload {
                    let response = match request {
                        api::model::Request::Containers => {
                            Response::Containers(self.list_containers().await)
                        }
                        api::model::Request::Install(_, _) => unreachable!(),
                        api::model::Request::Mount(_keys) => {
                            unimplemented!()
                        }
                        api::model::Request::Repositories => {
                            Response::Repositories(self.list_repositories())
                        }
                        api::model::Request::Shutdown => {
                            self.events_tx
                                .send(Event::Shutdown)
                                .await
                                .expect("Internal channel error on main");
                            Response::Ok(())
                        }
                        api::model::Request::Start(key) => match self.start(&key).await {
                            Ok(_) => Response::Ok(()),
                            Err(e) => {
                                warn!("Failed to start {}: {}", key, e);
                                Response::Err(e.into())
                            }
                        },
                        api::model::Request::Stop(key, timeout) => {
                            match self
                                .stop(&key, std::time::Duration::from_secs(*timeout))
                                .await
                            {
                                Ok(_) => Response::Ok(()),
                                Err(e) => {
                                    error!("Failed to stop {}: {}", key, e);
                                    Response::Err(e.into())
                                }
                            }
                        }
                        api::model::Request::Umount(key) => match self.umount(&key).await {
                            Ok(_) => api::model::Response::Ok(()),
                            Err(e) => {
                                warn!("Failed to unmount{}: {}", key, e);
                                api::model::Response::Err(e.into())
                            }
                        },
                        api::model::Request::Uninstall(key) => match self.uninstall(&key).await {
                            Ok(_) => api::model::Response::Ok(()),
                            Err(e) => {
                                warn!("Failed to uninstall {}: {}", key, e);
                                api::model::Response::Err(e.into())
                            }
                        },
                    };

                    // A error on the response_tx means that the connection
                    // was closed in the meantime. Ignore it.
                    response_tx.send(response).ok();
                } else {
                    warn!("Received message is not a request");
                }
            }
            Request::Install(repository, path) => {
                let payload = match self.install(&repository, &path).await {
                    Ok(_) => api::model::Response::Ok(()),
                    Err(e) => api::model::Response::Err(e.into()),
                };

                // A error on the response_tx means that the connection
                // was closed in the meantime. Ignore it.
                response_tx.send(payload).ok();
            }
        }
        Ok(())
    }

    async fn list_containers(&self) -> Vec<api::model::Container> {
        let mut containers = Vec::new();
        for repository in self.repositories.values() {
            for ((_, _), npk) in repository.npks() {
                let npk = Npk::from_path(npk, None).await.expect("Failed");
                let manifest = npk.manifest();
                let key = ContainerKey::new(
                    manifest.name.clone(),
                    manifest.version.clone(),
                    repository.id.clone(),
                );
                let process = self
                    .containers
                    .get(&key)
                    .and_then(|c| c.process.as_ref())
                    .map(|f| api::model::Process {
                        pid: f.process.pid(),
                        uptime: f.started.elapsed().as_nanos() as u64,
                        resources: api::model::Resources {
                            memory: {
                                {
                                    let page_size = page_size::get();
                                    let pid = f.process.pid();

                                    procinfo::pid::statm(pid as i32).ok().map(|statm| {
                                        api::model::Memory {
                                            size: (statm.size * page_size) as u64,
                                            resident: (statm.resident * page_size) as u64,
                                            shared: (statm.share * page_size) as u64,
                                            text: (statm.text * page_size) as u64,
                                            data: (statm.data * page_size) as u64,
                                        }
                                    })
                                }
                            },
                        },
                    });
                let mounted = self.containers.contains_key(&key);
                let c = api::model::Container::new(key, manifest.clone(), process, mounted);
                containers.push(c);
            }
        }
        containers
    }

    fn list_repositories(&self) -> HashMap<RepositoryId, api::model::Repository> {
        self.repositories
            .iter()
            .map(|(id, repository)| {
                (
                    id.clone(),
                    api::model::Repository::new(repository.dir.clone()),
                )
            })
            .collect()
    }

    async fn notification(&self, n: Notification) {
        self.events_tx
            .send(Event::Notification(n))
            .await
            .expect("Internal channel error on main");
    }
}

/// Dump the hello world npk created at compile time into a tmpdir that acts as internal
/// repository.
#[cfg(debug_assertions)]
async fn prepare_internal_repository(name: &str) -> Result<(tempfile::TempDir, Repository), Error> {
    let hello_world = include_bytes!(concat!(env!("OUT_DIR"), "/hello-world-0.0.1.npk"));
    let tempdir = tokio::task::block_in_place(|| {
        tempfile::tempdir().map_err(|e| Error::Io("Failed to create tmpdir".into(), e))
    })?;
    let dir = tempdir.path().to_owned();
    let npk = dir.join("hello_world-0.0.1.npk");

    tokio::fs::write(&npk, hello_world)
        .await
        .map_err(|e| Error::Io(format!("Failed to write {}", npk.display()), e))?;
    Ok((tempdir, Repository::new(name.to_owned(), dir, None).await?))
}
