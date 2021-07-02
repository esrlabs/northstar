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
    cgroups, config::Config, console::Request, error::Error, island::Island, key::PublicKey,
    mount::MountControl, repository::DirRepository, Container, Event, EventTx, ExitStatus,
    Notification, Pid, Repository, RepositoryId,
};
use crate::{
    api::{self, model::MountResult},
    runtime::repository::MemRepository,
};
use api::model::Response;
use async_trait::async_trait;
use bytes::Bytes;
use floating_duration::TimeAsFloat;
use futures::{
    future::{join_all, ready, Either},
    Future, FutureExt,
};
use log::{debug, error, info, warn};
use npk::manifest::{Autostart, Manifest, Mount, Resource};
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    fs::File,
    io::BufReader,
    iter::FromIterator,
    path::PathBuf,
    result,
    sync::Arc,
};
use tokio::{
    sync::{mpsc, oneshot},
    task, time,
};

const INTERNAL_REPOSITORY: &str = "internal";

type Repositories = HashMap<RepositoryId, Box<dyn Repository + Send + Sync>>;
pub(super) type Npk = npk::npk::Npk<BufReader<File>>;

#[async_trait]
pub(super) trait Process: Send + Sync + Debug {
    async fn pid(&self) -> Pid;
    async fn start(self: Box<Self>) -> Result<Box<dyn Process>, Error>;
    async fn stop(
        self: Box<Self>,
        timeout: time::Duration,
    ) -> Result<(Box<dyn Process>, ExitStatus), Error>;
    async fn destroy(self: Box<Self>) -> Result<(), Error>;
}

#[derive(Debug)]
pub(super) struct State<'a> {
    config: &'a Config,
    events_tx: EventTx,
    repositories: Repositories,
    containers: HashMap<Container, MountedContainer>,
    mount_control: Arc<MountControl>,
    launcher_island: Island,
}

#[derive(Debug)]
pub(super) enum BlockDevice {
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

#[derive(Debug)]
pub(super) struct ProcessContext {
    process: Box<dyn Process>,
    started: time::Instant,
    debug: super::debug::Debug,
    cgroups: Option<cgroups::CGroups>,
}

impl ProcessContext {
    async fn terminate(mut self, timeout: time::Duration) -> Result<ExitStatus, Error> {
        let (process, status) = self
            .process
            .stop(timeout)
            .await
            .expect("Failed to terminate process");

        process.destroy().await.expect("Failed to destroy process");

        self.debug.destroy().await?;

        if let Some(cgroups) = self.cgroups.take() {
            cgroups.destroy().await.expect("Failed to destroy cgroups")
        }

        Ok(status)
    }

    async fn destroy(mut self) {
        self.process
            .destroy()
            .await
            .expect("Failed to destroy process");

        self.debug
            .destroy()
            .await
            .expect("Failed to destroy debug utilities");

        if let Some(cgroups) = self.cgroups.take() {
            cgroups.destroy().await.expect("Failed to destroy cgroups")
        }
    }
}

impl<'a> State<'a> {
    /// Create a new empty State instance
    pub(super) async fn new(config: &'a Config, events_tx: EventTx) -> Result<State<'a>, Error> {
        let repositories = Repositories::default();
        let mount_control = Arc::new(MountControl::new(&config).await.map_err(Error::Mount)?);
        let launcher_island = Island::start(events_tx.clone(), config.clone())
            .await
            .expect("Failed to start launcher");

        let mut state = State {
            events_tx,
            repositories,
            containers: HashMap::new(),
            config,
            launcher_island,
            mount_control,
        };

        // Initialize repositories
        state.init_repositories().await?;

        // Start containers flagged with autostart
        state.autostart().await?;

        Ok(state)
    }

    async fn init_repositories(&mut self) -> Result<(), Error> {
        // Check if the configuration contains a repository with id INTERNAL_REPOSITORY if the hello-world
        // feature is enabled
        #[cfg(feature = "hello-world")]
        if self.config.repositories.contains_key(INTERNAL_REPOSITORY) {
            return Err(Error::Configuration(format!(
                "Duplicate repository {}",
                INTERNAL_REPOSITORY
            )));
        }

        // Build a map of repositories from the configuration
        for (id, repository) in &self.config.repositories {
            self.repositories.insert(
                id.clone(),
                Box::new(
                    DirRepository::new(
                        id.clone(),
                        repository.dir.clone(),
                        repository.key.as_deref(),
                    )
                    .await?,
                ),
            );
        }

        #[cfg(feature = "hello-world")]
        {
            info!("Adding hello-world to internal repository");
            let mut internal = MemRepository::default();
            let hello_world = include_bytes!(concat!(env!("OUT_DIR"), "/hello-world-0.0.1.npk"));
            internal
                .add_buf(hello_world)
                .await
                .expect("Failed to load hello-world");
            self.repositories
                .insert(INTERNAL_REPOSITORY.into(), Box::new(internal));
        }

        Ok(())
    }

    async fn autostart(&mut self) -> Result<(), Error> {
        // List of containers from all repositories with the autostart flag set
        let autostart = self
            .repositories
            .iter()
            .map(|(_, r)| r.containers())
            .flatten()
            .filter(|n| n.manifest().autostart.is_some())
            .map(|n| {
                (
                    Container::new(n.manifest().name.clone(), n.manifest().version.clone()),
                    n.manifest().autostart.as_ref().unwrap().clone(),
                )
            })
            .collect::<Vec<_>>();

        // Mount (parallel)
        let mut mounts = self
            .mount_all(&autostart.iter().map(|(c, _)| c.clone()).collect::<Vec<_>>())
            .await;

        for (result, (container, autostart)) in mounts.drain(..).zip(autostart) {
            match result {
                Ok(_) => {
                    info!("Autostarting {} ({:?})", container, autostart);
                    if let Err(e) = self.start(&container).await {
                        match autostart {
                            Autostart::Relaxed => {
                                warn!("Failed to autostart relaxed {}: {}", container, e);
                            }
                            Autostart::Critical => {
                                error!("Failed to autostart critical {}: {}", container, e);
                                return Err(e);
                            }
                        }
                    }
                }
                Err(e) => match autostart {
                    Autostart::Relaxed => {
                        warn!("Failed to mount relaxed {}: {}", container, e);
                    }
                    Autostart::Critical => {
                        error!("Failed to mount critical {}: {}", container, e);
                        return Err(e);
                    }
                },
            }
        }

        Ok(())
    }

    fn npk(&self, container: &Container) -> Option<(Arc<Npk>, Option<&PublicKey>)> {
        for repository in self.repositories.values() {
            if let Some(npk) = repository.get(container) {
                return Some((npk, repository.key()));
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
        let (npk, key) = self
            .npk(container)
            .ok_or_else(|| Error::InvalidContainer(container.clone()))?;

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
                    Mount::Resource(Resource { name, version, .. }) => {
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

        let npk = if let Some((npk, _)) = self.npk(container) {
            npk
        } else {
            return Err(Error::InvalidContainer(container.clone()));
        };

        // Check if the container is not a resource
        if npk.manifest().init.is_none() {
            warn!("Container {} is a resource", container);
            return Err(Error::StartContainerResource(container.clone()));
        }

        // The container to be started
        if let Some(mounted_container) = self.containers.get(container) {
            // Check if the container is already started
            if mounted_container.process.is_some() {
                warn!("Application {} is already running", container);
                return Err(Error::StartContainerStarted(container.clone()));
            }
        } else if !self.containers.contains_key(&container) {
            need_mount.insert(container.clone());
        }

        // Find resources
        for resource in npk.manifest().mounts.values().filter_map(|m| match m {
            Mount::Resource(Resource { name, version, .. }) => {
                Some(Container::new(name.clone(), version.clone()))
            }
            _ => None,
        }) {
            // Check if the resource is available
            if self.npk(&resource).is_none() {
                return Err(Error::StartContainerMissingResource(
                    container.clone(),
                    resource,
                ));
            }

            if !self.containers.contains_key(&resource) {
                need_mount.insert(resource.clone());
            }
        }

        info!(
            "Need to mount {} container before starting {}",
            need_mount.len(),
            container
        );

        for mount in self.mount_all(&Vec::from_iter(need_mount)).await {
            match mount {
                Ok(_) => (),
                Err(e) => {
                    warn!("Failed to mount: {}", e);
                    return Err(e);
                }
            }
        }

        // This must exist
        let mounted_container = self.containers.get(container).expect("Internal error");

        // Spawn process
        info!("Creating {}", container);
        let process = match self.launcher_island.create(&mounted_container).await {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to create process for {}", container);
                // Umount everything mounted so far for this start command
                warn!("Failed to start {}", container);
                return Err(e);
            }
        };

        // Debug
        let debug = super::debug::Debug::new(
            &self.config,
            &mounted_container.manifest,
            process.pid().await,
        )
        .await?;

        // CGroups
        let cgroups = if let Some(ref c) = mounted_container.manifest.cgroups {
            debug!("Configuring CGroups of {}", container);
            let cgroups =
                // Creating a cgroup is a northstar internal thing. If it fails it's not recoverable.
                cgroups::CGroups::new(&self.config.cgroups, &container, c, self.events_tx.clone())
                    .await.expect("Failed to create cgroup");

            // Assigning a pid to a cgroup created by us must work otherwise we did something wrong.
            cgroups
                .assign(process.pid().await)
                .await
                .expect("Failed to assign PID to cgroups");
            Some(cgroups)
        } else {
            None
        };

        // Signal the process to continue starting. This can fail because of the container content
        let process = match process.start().await {
            result::Result::Ok(process) => process,
            result::Result::Err(e) => {
                warn!("Failed to start {}: {}", container, e);
                debug.destroy().await.expect("Failed to destroy debug");
                if let Some(cgroups) = cgroups {
                    cgroups.destroy().await.expect("Failed to destroy cgroups");
                }
                return Err(e);
            }
        };

        let mounted_container = self.containers.get_mut(&container).unwrap();

        // Add process context to process
        mounted_container.process = Some(ProcessContext {
            process,
            started: time::Instant::now(),
            debug,
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
        if let Some(process) = self
            .containers
            .get_mut(&container)
            .and_then(|c| c.process.take())
        {
            info!("Terminating {}", container);
            let exit_status = process.terminate(timeout).await.expect("Failed to stop");

            // Send notification to main loop
            self.notification(Notification::Stopped(container.clone()))
                .await;

            info!("Stopped {} with status {:?}", container, exit_status);

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

        self.launcher_island.shutdown().await
    }

    /// Install an NPK
    async fn install(
        &mut self,
        repository_id: &str,
        rx: &mut mpsc::Receiver<Bytes>,
    ) -> Result<(), Error> {
        // Find the repository
        let repository = self
            .repositories
            .get_mut(repository_id)
            .ok_or_else(|| Error::InvalidRepository(repository_id.to_string()))?;

        // Add the npk to the repository
        let container = repository.insert(rx).await?;

        info!("Successfully installed {}", container);

        Ok(())
    }

    /// Remove and umount a specific app
    #[allow(clippy::blocks_in_if_conditions)]
    async fn uninstall(&mut self, container: &Container) -> result::Result<(), Error> {
        info!("Trying to uninstall {}", container);

        if self.containers.contains_key(container) {
            self.umount(container).await?;
        }

        for repository in self.repositories.values_mut() {
            repository.remove(container).await?;
        }

        info!("Successfully uninstalled {}", container);

        Ok(())
    }

    /// Handle the exit of a container. The restarting of containers is a subject
    /// to be removed and handled externally
    pub(super) async fn on_exit(
        &mut self,
        container: Container,
        exit_status: ExitStatus,
    ) -> Result<(), Error> {
        if let Some(mounted_container) = self.containers.get_mut(&container) {
            if let Some(process) = mounted_container.process.take() {
                let critical = mounted_container.manifest.autostart == Some(Autostart::Critical);
                if critical {
                    error!(
                        "Critical process {} exited after {:?} with status {:?}",
                        container,
                        process.started.elapsed(),
                        exit_status,
                    );
                } else {
                    info!(
                        "Process {} exited after {:?} with status {:?}",
                        container,
                        process.started.elapsed(),
                        exit_status,
                    );
                }

                process.destroy().await;

                self.notification(Notification::Exit {
                    container: container.clone(),
                    status: exit_status.clone(),
                })
                .await;

                // This is a critical flagged container that exited with a error exit code. That's not good...
                if !exit_status.success() && critical {
                    return Err(Error::CriticalContainer(container, exit_status));
                }
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

    async fn mount_all(&mut self, containers: &[Container]) -> Vec<Result<Container, Error>> {
        let mut mounts = Vec::with_capacity(containers.len());

        // Create mount futures
        for c in containers {
            // Containers cannot be mounted twice
            if self.containers.contains_key(c) {
                mounts.push(Either::Right(ready(Err(Error::MountBusy(c.clone())))));
            } else {
                let m = match self.mount(c).await {
                    Ok(m) => Either::Left(m),
                    Err(e) => Either::Right(ready(Err(e))),
                };
                mounts.push(m);
            }
        }

        // Insert all mounted containers into containers map
        join_all(mounts)
            .await
            .drain(..)
            .zip(containers)
            .map(|(r, c)| {
                match r {
                    Ok(c) => {
                        // Add mounted container to our internal housekeeping
                        info!("Mounted {}", c.container);
                        let container = c.container.clone();
                        self.containers.insert(container.clone(), c);
                        Ok(container)
                    }
                    Err(e) => {
                        warn!("Failed to mount {}: {}", c, e);
                        Err(e)
                    }
                }
            })
            .collect()
    }

    /// Process console events
    pub(super) async fn console_request(
        &mut self,
        request: &mut Request,
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
                            let result = self
                                .mount_all(containers)
                                .await
                                .drain(..)
                                .zip(containers)
                                .map(|(r, c)| match r {
                                    Ok(r) => MountResult::Ok(r),
                                    Err(e) => MountResult::Err((c.clone(), e.into())),
                                })
                                .collect();
                            Response::Mount(result)
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
            Request::Install(repository, ref mut rx) => {
                let payload = match self.install(&repository, rx).await {
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
            for npk in repository.containers() {
                let manifest = npk.manifest();
                let container = Container::new(manifest.name.clone(), manifest.version.clone());
                let process = self
                    .containers
                    .get(&container)
                    .and_then(|c| c.process.as_ref())
                    .map(|f| {
                        let pid = futures::executor::block_on(f.process.pid());
                        api::model::Process {
                            pid,
                            uptime: f.started.elapsed().as_nanos() as u64,
                            resources: api::model::Resources {
                                memory: {
                                    {
                                        let page_size = page_size::get();
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
                        }
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

    fn list_repositories(&self) -> HashSet<RepositoryId> {
        self.repositories.keys().cloned().collect()
    }

    async fn notification(&self, n: Notification) {
        if !self.events_tx.is_closed() {
            self.events_tx
                .send(Event::Notification(n))
                .await
                .expect("Internal channel error on main");
        }
    }
}
