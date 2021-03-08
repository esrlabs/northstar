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
    key::PublicKey,
    minijail::{Minijail, Process},
    mount::MountControl,
    Container, Event, EventTx, ExitStatus, Notification, Repository, RepositoryId,
};
use api::model::Response;
use floating_duration::TimeAsFloat;
use futures::{
    future::{join_all, ready},
    Future, FutureExt,
};
use log::{debug, error, info, warn};
use npk::{
    manifest::{Manifest, Mount},
    npk::Npk,
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::{Path, PathBuf},
    result,
    sync::Arc,
};
use tokio::{sync::oneshot, task, time};

#[derive(Debug)]
pub(super) struct State<'a> {
    config: &'a Config,
    minijail: Minijail<'a>,
    mount_control: Arc<MountControl>,
    events_tx: EventTx,
    repositories: HashMap<RepositoryId, Repository>,
    containers: HashMap<Container, MountedContainer>,
    /// Internal test repository tempdir
    #[cfg(feature = "hello")]
    internal_repository: tempfile::TempDir,
}

#[derive(Debug)]
pub enum BlockDevice {
    Loopback(PathBuf),
    Verity(PathBuf),
}

#[derive(Debug)]
pub(super) struct MountedContainer {
    pub(super) container: Container,
    pub(super) manifest: Manifest,
    pub(super) root: PathBuf,
    pub(super) device: BlockDevice,
    pub(super) process: Option<ProcessContext>,
}

impl fmt::Display for MountedContainer {
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
        #[cfg(feature = "hello-world")]
        #[cfg(debug_assertions)]
        let internal_repository = {
            let name = "hello-world".to_string();
            let (dir, repository) = prepare_internal_repository(&name).await?;
            repositories.insert(name, repository);
            dir
        };

        // Build a map of repositories from the configuration
        for (id, repository) in &config.repositories {
            repositories.insert(
                id.clone(),
                Repository::new(
                    id.clone(),
                    repository.dir.clone(),
                    repository.key.as_deref(),
                )
                .await?,
            );
        }

        // TODO: Verify that the containers in all repositories are unique with name and version

        let minijail = Minijail::new(events_tx.clone(), config)
            .await
            .map_err(Error::Process)?;
        let mount_control = MountControl::new(&config).await.map_err(Error::Mount)?;

        Ok(State {
            events_tx,
            repositories,
            containers: HashMap::new(),
            config,
            minijail,
            mount_control: Arc::new(mount_control),
            #[cfg(feature = "hello-world")]
            internal_repository,
        })
    }

    fn npk(&self, container: &Container) -> Option<(&Path, &Npk, Option<&PublicKey>)> {
        for repository in self.repositories.values() {
            if let Some(path) = repository.containers.get(container) {
                let npk = repository.npks.get(container)?;
                return Some((path, npk, repository.key.as_ref()));
            }
        }
        None
    }

    /// Mount `container`
    async fn mount(
        &self,
        container: &Container,
    ) -> Result<impl Future<Output = Result<MountedContainer, Error>>, Error> {
        // Find npk and optional key
        let (npk, _, key) = self
            .npk(container)
            .ok_or_else(|| Error::InvalidContainer(container.clone()))?;

        // TODO: Reuse Npk stored in the repository and do not open again. This changed
        // implies some lifetime changes due to the movement into the mount task.
        // Load NPK
        let npk = Npk::from_path(npk, key).await.map_err(Error::Npk)?;
        let manifest = npk.manifest().clone();

        // Try to mount the npk found. If this fails return with an error - nothing needs to
        // be cleaned up.
        let root = self.config.run_dir.join(container.to_string());
        let mount_control = self.mount_control.clone();
        let container = container.clone();
        let key = key.cloned();
        let task = task::spawn(async move {
            let device = mount_control
                .mount(npk, &root, key.as_ref())
                .await
                .await
                .map_err(Error::Mount)
                .map(|device| {
                    if key.is_some() {
                        BlockDevice::Verity(device)
                    } else {
                        BlockDevice::Loopback(device)
                    }
                })?;

            Ok(MountedContainer {
                container: container.clone(),
                manifest,
                root,
                device,
                process: None,
            })
        })
        .then(|r| ready(r.expect("Internal task join error")));

        Ok(task)
    }

    /// Umount a given container
    #[allow(clippy::blocks_in_if_conditions)]
    async fn umount(&mut self, container: &Container) -> Result<(), Error> {
        let mounted_container = self
            .containers
            .get(container)
            .ok_or_else(|| Error::UmountBusy(container.clone()))?;
        info!("Umounting {}", container);
        // Check if the application is started - if yes it cannot be uninstalled
        if mounted_container.process.is_some() {
            return Err(Error::UmountBusy(container.clone()));
        }

        // If this is a resource check if it can be uninstalled or if it's
        // used by any (mounted) container. The not mounted containers are
        // not interesting because the check for all resources is done when
        // it's mounted/started.
        if mounted_container.manifest.init.is_none()
            && self
                .containers
                .values()
                .filter(|c| c.process.is_some()) // Just started containers count
                .map(|c| &c.manifest.mounts)
                .flatten() // A iter of Mounts
                .map(|(_, mount)| mount)
                .filter_map(|mount| match mount {
                    Mount::Resource { name, version, .. } => {
                        Some(Container::new(name.clone(), version.clone()))
                    }
                    _ => None,
                })
                .any(|c| &c == container)
        {
            warn!("Failed to umount busy resource container {}", container);
            return Err(Error::UmountBusy(container.clone()));
        }

        // If the container is mounted with verity this needs to be passed to the umount
        // code in order to wait for the verity device removal
        let verity_device = match mounted_container.device {
            BlockDevice::Loopback(_) => None,
            BlockDevice::Verity(ref device) => Some(device.as_path()),
        };
        self.mount_control
            .umount(&mounted_container.root, verity_device)
            .await
            .expect("Failed to umount");
        self.containers.remove(container);
        Ok(())
    }

    pub(super) async fn start(&mut self, container: &Container) -> Result<(), Error> {
        let start = time::Instant::now();
        info!("Trying to start {}", container);

        let mut need_mount = HashSet::new();

        if let Some((_, npk, _)) = self.npk(container) {
            let manifest = npk.manifest();

            // The the to be started container
            if let Some(mounted_container) = self.containers.get(container) {
                // Check if the container is not a resouce
                if mounted_container.manifest.init.is_none() {
                    warn!("Container {} is a resource", container);
                    return Err(Error::StartContainerResource(container.clone()));
                }

                // Check if the container is already started
                if mounted_container.process.is_some() {
                    warn!("Application {} is already running", container);
                    return Err(Error::StartContainerStarted(container.clone()));
                }
            } else {
                need_mount.insert(container.clone());
            }

            // Find to be mounted resources
            for resource in manifest
                .mounts
                .values()
                .filter_map(|m| match m {
                    Mount::Resource { name, version, .. } => {
                        Some(Container::new(name.clone(), version.clone()))
                    }
                    _ => None,
                })
                .filter(|resource| !self.containers.contains_key(resource))
            // Only not yet mounted ones
            {
                // Check if the resource is available
                if self.npk(&resource).is_none() {
                    return Err(Error::StartContainerMissingResource(
                        container.clone(),
                        resource,
                    ));
                }
                need_mount.insert(resource.clone());
            }
        } else {
            return Err(Error::InvalidContainer(container.clone()));
        }

        info!(
            "Need to mount {} container before starting {}",
            need_mount.len(),
            container
        );

        // Prepare a list of futures that actually mount
        let mut mounts = Vec::new();
        for to_be_mounted in &need_mount {
            let mount = self
                .mount(&to_be_mounted)
                .await?
                .map(move |r| (to_be_mounted, r)); // Add the container identification to the futures result
            mounts.push(mount);
        }

        // Mount :-)
        let mounts = join_all(mounts).await;

        // Split into succesful and failed ones
        let (ok, mut failed): (Vec<_>, Vec<_>) =
            mounts.into_iter().partition(|(_, result)| !result.is_err());

        // Log mounts and insert into the list of mounted containers
        for (container, mounted_container) in ok {
            debug!("Successfully mounted {}", container);
            self.containers
                .insert(container.clone(), mounted_container.unwrap());
        }

        // Log failures
        for (container, err) in &failed {
            debug!(
                "Failed to mount {}: {}",
                container,
                err.as_ref().err().unwrap()
            );
        }

        // At least one mount failed. Abort...
        // TODO: All the errors should be returned
        if let Some((_, Err(e))) = failed.pop() {
            return Err(e);
        }

        // This must exist
        let mouted_container = self.containers.get(container).expect("Internal error");

        // Spawn process
        info!("Creating {}", container);
        let mut process = match self
            .minijail
            .create(&mouted_container)
            .await
            .map_err(Error::Process)
        {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to create process for {}", container);
                // Umount everything mounted so far for this start command
                warn!("Failed to start {}", container);
                return Err(e);
            }
        };

        // CGroups
        let cgroups = if let Some(ref c) = mouted_container.manifest.cgroups {
            debug!("Configuring CGroups of {}", container);
            let cgroups =
                // Creating a cgroup is a northstar internal thing. If it fails it's not recoverable.
                super::cgroups::CGroups::new(&self.config.cgroups, &container, c, self.events_tx.clone())
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
            warn!("Failed to resume process of {}", container);
            warn!("Failed to start {}", container);
            return Err(e);
        }

        let mounted_container = self.containers.get_mut(&container).unwrap();

        // Add process context to process
        mounted_container.process = Some(ProcessContext {
            process,
            started: time::Instant::now(),
            cgroups,
        });

        info!(
            "Started {} in {:.03}s",
            container,
            start.elapsed().as_fractional_secs()
        );

        self.notification(Notification::Started(container.clone()))
            .await;

        Ok(())
    }

    /// Stop a application. Timeout specifies the time until the process is
    /// SIGKILLed if it doesn't exit when receiving a SIGTERM
    pub(super) async fn stop(
        &mut self,
        container: &Container,
        timeout: time::Duration,
    ) -> Result<(), Error> {
        if let Some(mut context) = self
            .containers
            .get_mut(&container)
            .and_then(|c| c.process.take())
        {
            info!("Stopping {}", container);
            let status = context
                .process
                .terminate(timeout)
                .await
                .map_err(Error::Process)
                .expect("Failed to terminate process");

            context.destroy().await.expect("Failed to destroy context");

            // Send notification to main loop
            self.notification(Notification::Stopped(container.clone()))
                .await;

            info!("Stopped {} with status {}", container, status);

            Ok(())
        } else {
            Err(Error::StopContainerNotStarted(container.clone()))
        }
    }

    /// Shutdown the runtime: stop running applications and umount npks
    pub(super) async fn shutdown(mut self) -> Result<(), Error> {
        // Stop started containers
        let started = self
            .containers
            .iter()
            .filter_map(|(container, mounted_container)| {
                mounted_container.process.as_ref().map(|_| container)
            })
            .cloned()
            .collect::<Vec<_>>();
        // Stop started applications
        for container in &started {
            self.stop(&container, time::Duration::from_secs(5)).await?;
        }

        let containers = self.containers.keys().cloned().collect::<Vec<_>>();
        for container in &containers {
            self.umount(container).await?;
        }

        self.minijail.shutdown().await.map_err(Error::Process)
    }

    /// Install an NPK
    async fn install(&mut self, repository_id: &str, src: &Path) -> Result<(), Error> {
        debug!("Trying to install {}", src.display());
        // Find the repository
        let repository = self
            .repositories
            .get(repository_id)
            .ok_or_else(|| Error::InvalidRepository(repository_id.to_string()))?;
        // Load the npk to indentify name and version
        let npk = Npk::from_path(src, repository.key.as_ref())
            .await
            .map_err(Error::Npk)?;

        // Construct a container key for the new npk
        let manifest = npk.manifest();
        let container = Container::new(manifest.name.clone(), manifest.version.clone());

        // Check if the container already exists or if this is a duplicate install attempt
        if self
            .repositories
            .values()
            .any(|r| r.containers.contains_key(&container))
        {
            warn!("Container {} is already installed", container);
            return Err(Error::InstallDuplicate(container.clone()));
        }

        debug!("NPK contains {}", container);

        // Add the npk to the repository
        self.repositories
            .get_mut(repository_id)
            .unwrap()
            .add(&container, src)
            .await?;

        debug!("Successfully installed {}", container);

        Ok(())
    }

    /// Remove and umount a specific app
    #[allow(clippy::blocks_in_if_conditions)]
    async fn uninstall(&mut self, container: &Container) -> result::Result<(), Error> {
        debug!("Trying to uninstall {}", container);

        if self.containers.contains_key(container) {
            self.umount(container).await?;
        }

        for repository in self.repositories.values_mut() {
            if repository.containers.contains_key(container) {
                repository.remove(container).await?;
            }
        }

        debug!("Successfully uninstalled {}", container);

        Ok(())
    }

    /// Handle the exit of a container. The restarting of containers is a subject
    /// to be removed and handled externally
    pub(super) async fn on_exit(
        &mut self,
        container: &Container,
        status: &ExitStatus,
    ) -> Result<(), Error> {
        if let Some(mounted_container) = self.containers.get_mut(&container) {
            if let Some(context) = mounted_container.process.take() {
                info!(
                    "Process {} exited after {:?} with status {:?}",
                    container,
                    context.started.elapsed(),
                    status,
                );

                context.destroy().await.expect("Failed to destroy context");

                self.notification(Notification::Exit {
                    container: container.clone(),
                    status: status.clone(),
                })
                .await;
            }
        }
        Ok(())
    }

    /// Handle out of memory conditions for container `name`
    pub(super) async fn on_oom(&mut self, container: &Container) -> Result<(), Error> {
        if self
            .containers
            .get(container)
            .and_then(|c| c.process.as_ref())
            .is_some()
        {
            warn!("Process {} is out of memory. Stopping", container);
            self.notification(Notification::OutOfMemory(container.clone()))
                .await;
            self.stop(container, time::Duration::from_secs(5)).await?;
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
                        api::model::Request::Mount(containers) => {
                            // Collect mount futures
                            let mut mounts = vec![];
                            for container in containers {
                                mounts.push(self.mount(container).await?);
                            }

                            // Mount ;-)
                            let results = join_all(mounts).await;

                            for result in results {
                                match result {
                                    Ok(mounted_container) => {
                                        // Add mounted container to our internal housekeeping
                                        info!("Mounted {}", mounted_container.container);
                                        self.containers.insert(
                                            mounted_container.container.clone(),
                                            mounted_container,
                                        );
                                    }
                                    Err(_) => {
                                        warn!(
                                            "Not yet implemented: error handling for bulk mounts"
                                        );
                                    }
                                }
                            }
                            Response::Mount(vec![])
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
                        api::model::Request::Start(container) => match self.start(&container).await
                        {
                            Ok(_) => Response::Ok(()),
                            Err(e) => {
                                warn!("Failed to start {}: {}", container, e);
                                Response::Err(e.into())
                            }
                        },
                        api::model::Request::Stop(container, timeout) => {
                            match self
                                .stop(&container, std::time::Duration::from_secs(*timeout))
                                .await
                            {
                                Ok(_) => Response::Ok(()),
                                Err(e) => {
                                    error!("Failed to stop {}: {}", container, e);
                                    Response::Err(e.into())
                                }
                            }
                        }
                        api::model::Request::Umount(container) => {
                            match self.umount(&container).await {
                                Ok(_) => api::model::Response::Ok(()),
                                Err(e) => {
                                    warn!("Failed to unmount{}: {}", container, e);
                                    api::model::Response::Err(e.into())
                                }
                            }
                        }
                        api::model::Request::Uninstall(container) => {
                            match self.uninstall(&container).await {
                                Ok(_) => api::model::Response::Ok(()),
                                Err(e) => {
                                    warn!("Failed to uninstall {}: {}", container, e);
                                    api::model::Response::Err(e.into())
                                }
                            }
                        }
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

    async fn list_containers(&self) -> Vec<api::model::ContainerData> {
        let mut containers = Vec::new();
        for (repository_name, repository) in &self.repositories {
            for npk in repository.containers.values() {
                let npk = Npk::from_path(npk, None).await.expect("Failed to read npk");
                let manifest = npk.manifest();
                let container = Container::new(manifest.name.clone(), manifest.version.clone());
                let process = self
                    .containers
                    .get(&container)
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
                let mounted = self.containers.contains_key(&container);
                let c = api::model::ContainerData::new(
                    container,
                    repository_name.into(),
                    manifest.clone(),
                    process,
                    mounted,
                );
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
#[cfg(feature = "hello-world")]
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
