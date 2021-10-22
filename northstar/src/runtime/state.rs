use super::{
    cgroups,
    config::{Config, RepositoryType},
    console::Request,
    error::Error,
    mount::{MountControl, MountInfo},
    process::Launcher,
    repository::{DirRepository, MemRepository},
    stats::ContainerStats,
    Container, ContainerEvent, Event, EventTx, ExitStatus, NotificationTx, Pid, Repository,
    RepositoryId,
};
use crate::{
    api::{self, model::MountResult},
    common::non_null_string::NonNullString,
    npk,
    npk::manifest::{Autostart, Mount, Resource},
    runtime::{error::Context, CGroupEvent, ENV_NAME, ENV_VERSION},
};
use api::model::Response;
use async_trait::async_trait;
use bytes::Bytes;
use floating_duration::TimeAsFloat;
use futures::{
    executor::{ThreadPool, ThreadPoolBuilder},
    future::{join_all, ready, Either},
    task::SpawnExt,
    Future,
};
use log::{debug, error, info, warn};
use nix::sys::signal::Signal;
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
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
    time,
};
use Signal::SIGKILL;

type Repositories = HashMap<RepositoryId, Box<dyn Repository + Send + Sync>>;
pub(super) type Npk = npk::npk::Npk<BufReader<File>>;

#[async_trait]
pub(super) trait Process: Send + Sync + Debug {
    fn pid(&self) -> Pid;
    async fn spawn(&mut self) -> Result<(), Error>;
    async fn kill(&mut self, signal: Signal) -> Result<(), Error>;
    async fn wait(&mut self) -> Result<ExitStatus, Error>;
    async fn destroy(&mut self) -> Result<(), Error>;
}

#[derive(Debug)]
pub(super) struct State<'a> {
    config: &'a Config,
    events_tx: EventTx,
    notification_tx: NotificationTx,
    repositories: Repositories,
    containers: HashMap<Container, MountedContainer>,
    mount_control: Arc<MountControl>,
    launcher: Launcher,
    executor: ThreadPool,
}

#[derive(Debug)]
pub(super) struct MountedContainer {
    pub(super) root: PathBuf,
    pub(super) mount_info: MountInfo,
    pub(super) process: Option<ProcessContext>,
}

#[derive(Debug)]
pub(super) struct ProcessContext {
    process: Box<dyn Process>,
    started: time::Instant,
    debug: super::debug::Debug,
    cgroups: cgroups::CGroups,
}

impl ProcessContext {
    async fn kill(&mut self, signal: Signal) -> Result<(), Error> {
        self.process.kill(signal).await
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

        self.cgroups.destroy().await;
    }
}

impl<'a> State<'a> {
    /// Create a new empty State instance
    pub(super) async fn new(
        config: &'a Config,
        events_tx: EventTx,
        notification_tx: NotificationTx,
    ) -> Result<State<'a>, Error> {
        let repositories = Repositories::default();
        let mount_control = Arc::new(MountControl::new().await.map_err(Error::Mount)?);
        let launcher = Launcher::start(events_tx.clone(), config.clone(), notification_tx.clone())
            .await
            .expect("Failed to start launcher");
        let executor = ThreadPoolBuilder::new()
            .name_prefix("northstar")
            .create()
            .expect("Failed to start thread pool");

        let mut state = State {
            events_tx,
            notification_tx,
            repositories,
            containers: HashMap::new(),
            config,
            launcher,
            mount_control,
            executor,
        };

        state.init_repositories().await?;

        // Start containers flagged with autostart
        state.autostart().await?;

        Ok(state)
    }

    async fn init_repositories(&mut self) -> Result<(), Error> {
        let mut blacklist = HashSet::new();

        // Build a map of repositories from the configuration
        for (id, repository) in &self.config.repositories {
            match &repository.r#type {
                RepositoryType::Fs { dir } => {
                    let repository =
                        DirRepository::new(id.clone(), dir, repository.key.as_deref(), &blacklist)
                            .await?;
                    blacklist.extend(repository.list());
                    self.repositories.insert(id.clone(), Box::new(repository));
                }
                RepositoryType::Memory => {
                    let repository =
                        MemRepository::new(id.clone(), repository.key.as_deref()).await?;
                    self.repositories.insert(id.clone(), Box::new(repository));
                }
            }
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
                    if let Err(e) = self.start(&container, None, None).await {
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

    /// Find the container's NPK
    fn find_npk(&self, container: &Container) -> Option<Arc<Npk>> {
        self.repositories.values().find_map(|r| r.get(container))
    }

    /// Find the repository that has the given container
    fn find_repository(&self, container: &Container) -> Option<&(dyn Repository + Send + Sync)> {
        self.repositories
            .values()
            .find_map(|r| r.get(container).is_some().then(|| r.as_ref()))
    }

    /// Mount `container`
    async fn mount(
        &self,
        container: &Container,
    ) -> Result<impl Future<Output = Result<MountedContainer, Error>>, Error> {
        // Find the repository that has the container
        let repository = self
            .find_repository(container)
            .ok_or_else(|| Error::InvalidContainer(container.clone()))?;
        let key = repository.key().cloned();
        let npk = repository.get(container).unwrap();

        // Try to mount the npk found. If this fails return with an error - nothing needs to
        // be cleaned up.
        let root = self.config.run_dir.join(container.to_string());
        let mount_control = self.mount_control.clone();
        let mount = async move {
            let mount_info = mount_control
                .mount(npk, &root, key.as_ref())
                .await
                .map_err(Error::Mount)?;

            Ok(MountedContainer {
                root,
                mount_info,
                process: None,
            })
        };

        Ok(mount)
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

        let npk = self.find_npk(container).unwrap();
        let manifest = npk.manifest();

        // If this is a resource check if it can be uninstalled or if it's
        // used by any (mounted) container. The not mounted containers are
        // not interesting because the check for all resources is done when
        // it's mounted/started.
        if manifest.init.is_none()
            && self
                .running_containers()
                .filter_map(|container| {
                    self.find_npk(container)
                        .map(|n| n.manifest().clone().mounts)
                })
                .flatten() // A iter of Mounts
                .map(|(_, mount)| mount)
                .filter_map(|mount| match mount {
                    Mount::Resource(Resource { name, version, .. }) => {
                        Some(Container::new(name, version))
                    }
                    _ => None,
                })
                .any(|c| &c == container)
        {
            warn!("Failed to umount busy resource container {}", container);
            return Err(Error::UmountBusy(container.clone()));
        }

        self.mount_control
            .umount(&mounted_container.mount_info)
            .await
            .expect("Failed to umount");
        self.containers.remove(container);
        Ok(())
    }

    /// Start a container
    /// `container`: Container to start
    /// `args`: Optional command line arguments that overwrite the values from the manifest
    /// `env`: Optional env variables that overwrite the values from the manifest
    pub(super) async fn start(
        &mut self,
        container: &Container,
        args: Option<&Vec<NonNullString>>,
        env: Option<&HashMap<NonNullString, NonNullString>>,
    ) -> Result<(), Error> {
        let start = time::Instant::now();
        info!("Trying to start {}", container);

        let mut need_mount = HashSet::new();

        let npk = self
            .find_npk(container)
            .ok_or_else(|| Error::InvalidContainer(container.clone()))?;

        // Check optional env variables for reserved ENV_NAME or ENV_VERSION key which cannot be overwritten
        if let Some(env) = env {
            if env
                .keys()
                .any(|k| k.as_str() == ENV_NAME || k.as_str() == ENV_VERSION)
            {
                return Err(Error::InvalidArguments(format!(
                    "env contains reserved key {} or {}",
                    ENV_NAME, ENV_VERSION
                )));
            }
        }

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
        } else if !self.containers.contains_key(container) {
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
            if self.find_npk(&resource).is_none() {
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
        let npk = self.find_npk(container).unwrap();
        let manifest = npk.manifest();

        // Spawn process
        info!("Creating {}", container);
        let root = mounted_container
            .root
            .canonicalize()
            .expect("Failed to canonicalize root");

        let mut process = match self
            .launcher
            .create(root, container.clone(), manifest.clone(), args, env)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to create process for {}", container);
                // Umount everything mounted so far for this start command
                warn!("Failed to start {}", container);
                return Err(e);
            }
        };
        let pid = process.pid();

        // Debug
        let debug = super::debug::Debug::new(self.config, manifest, pid).await?;

        // CGroups
        let cgroups = {
            debug!("Configuring CGroups for {}", container);
            let config = manifest.cgroups.clone().unwrap_or_default();

            // Creating a cgroup is a northstar internal thing. If it fails it's not recoverable.
            cgroups::CGroups::new(
                &self.config.cgroup,
                self.events_tx.clone(),
                container,
                &config,
                pid,
            )
            .await
            .expect("Failed to create cgroup")
        };

        // Signal the process to continue starting. This can fail because of the container content
        match process.spawn().await {
            result::Result::Ok(process) => process,
            result::Result::Err(e) => {
                warn!("Failed to start {} ({}): {}", container, pid, e);
                debug.destroy().await.expect("Failed to destroy debug");
                cgroups.destroy().await;
                return Err(e);
            }
        };

        let mounted_container = self.containers.get_mut(container).unwrap();

        // Add process context to process
        mounted_container.process = Some(ProcessContext {
            process: Box::new(process),
            started: time::Instant::now(),
            debug,
            cgroups,
        });

        info!(
            "Started {} ({}) in {:.03}s",
            container,
            pid,
            start.elapsed().as_fractional_secs()
        );

        self.container_event(container, ContainerEvent::Started);

        Ok(())
    }

    /// Terminate container
    pub(super) async fn kill(
        &mut self,
        container: &Container,
        signal: Signal,
    ) -> Result<(), Error> {
        if let Some(process) = self
            .containers
            .get_mut(container)
            .and_then(|c| c.process.as_mut())
        {
            info!("Killing {} with {}", container, signal.as_str());
            process.kill(signal).await
        } else {
            Err(Error::StopContainerNotStarted(container.clone()))
        }
    }

    /// Shutdown the runtime: stop running applications and umount npks
    pub(super) async fn shutdown(mut self) -> Result<(), Error> {
        let to_umount = self.containers.keys().cloned().collect::<Vec<_>>();

        for (container, mounted) in self.containers.iter_mut() {
            if let Some(mut context) = mounted.process.take() {
                let pid = context.process.pid();
                info!("Sending SIGKILL to {} ({})", container, pid);
                nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), SIGKILL).ok();

                info!("Waiting for {} to exit", container);
                let exit_status =
                    time::timeout(time::Duration::from_secs(10), context.process.wait())
                        .await
                        .context(format!("Killing {}", container))?;
                debug!("Container {} terminated with {:?}", container, exit_status);
                context.destroy().await;
            }
        }

        for container in &to_umount {
            self.umount(container).await?;
        }

        self.launcher.shutdown().await?;

        Ok(())
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

        self.container_event(&container, ContainerEvent::Installed);

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

        self.container_event(container, ContainerEvent::Uninstalled);

        Ok(())
    }

    async fn container_stats(
        &mut self,
        container: &Container,
    ) -> result::Result<ContainerStats, Error> {
        if let Some(process) = self
            .containers
            .get(container)
            .and_then(|c| c.process.as_ref())
        {
            info!("Collecting stats of {}", container);
            let stats = process.cgroups.stats();
            Ok(stats)
        } else {
            Err(Error::StopContainerNotStarted(container.clone()))
        }
    }

    /// Handle the exit of a container. The restarting of containers is a subject
    /// to be removed and handled externally
    async fn on_exit(
        &mut self,
        container: &Container,
        exit_status: &ExitStatus,
    ) -> Result<(), Error> {
        let npk = self.find_npk(container).unwrap();
        let manifest = npk.manifest();

        if let Some(mounted_container) = self.containers.get_mut(container) {
            if let Some(process) = mounted_container.process.take() {
                let critical = manifest.autostart == Some(Autostart::Critical);
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

                self.container_event(container, ContainerEvent::Exit(exit_status.clone()));

                // This is a critical flagged container that exited with a error exit code. That's not good...
                if !exit_status.success() && critical {
                    return Err(Error::CriticalContainer(
                        container.clone(),
                        exit_status.clone(),
                    ));
                }
            }
        }
        Ok(())
    }

    // Handle global events
    pub(super) async fn on_event(
        &mut self,
        container: &Container,
        event: &ContainerEvent,
    ) -> Result<(), Error> {
        match event {
            ContainerEvent::Started => (),
            ContainerEvent::Exit(exit_status) => {
                self.on_exit(container, exit_status).await?;
            }
            ContainerEvent::Installed => (),
            ContainerEvent::Uninstalled => (),
            ContainerEvent::CGroup(CGroupEvent::Memory(_)) => {
                warn!("Process {} is out of memory", container);
            }
        }

        Ok(())
    }

    /// Process console events
    pub(super) async fn on_request(
        &mut self,
        request: &mut Request,
        response_tx: oneshot::Sender<api::model::Response>,
    ) -> Result<(), Error> {
        match request {
            Request::Message(message) => {
                if let api::model::Message::Request(ref request) = message {
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
                        api::model::Request::Start(container, args, env) => {
                            match self.start(container, args.as_ref(), env.as_ref()).await {
                                Ok(_) => Response::Ok(()),
                                Err(e) => {
                                    warn!("Failed to start {}: {}", container, e);
                                    Response::Err(e.into())
                                }
                            }
                        }
                        api::model::Request::Kill(container, signal) => {
                            let signal = Signal::try_from(*signal).unwrap();
                            match self.kill(container, signal).await {
                                Ok(_) => Response::Ok(()),
                                Err(e) => {
                                    error!("Failed to kill {} with {}: {}", container, signal, e);
                                    Response::Err(e.into())
                                }
                            }
                        }
                        api::model::Request::Umount(container) => {
                            match self.umount(container).await {
                                Ok(_) => api::model::Response::Ok(()),
                                Err(e) => {
                                    warn!("Failed to unmount{}: {}", container, e);
                                    api::model::Response::Err(e.into())
                                }
                            }
                        }
                        api::model::Request::Uninstall(container) => {
                            match self.uninstall(container).await {
                                Ok(_) => api::model::Response::Ok(()),
                                Err(e) => {
                                    warn!("Failed to uninstall {}: {}", container, e);
                                    api::model::Response::Err(e.into())
                                }
                            }
                        }
                        api::model::Request::ContainerStats(container) => {
                            match self.container_stats(container).await {
                                Ok(stats) => {
                                    api::model::Response::ContainerStats(container.clone(), stats)
                                }
                                Err(e) => {
                                    warn!("Failed to gather stats for {}: {}", container, e);
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
                let payload = match self.install(repository, rx).await {
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

        // Spawn mount tasks onto the executor
        let mounts = mounts
            .drain(..)
            .map(|t| self.executor.spawn_with_handle(t).unwrap());

        // Insert all mounted containers into containers map
        join_all(mounts)
            .await
            .drain(..)
            .zip(containers)
            .map(|(r, container)| {
                match r {
                    Ok(mounted) => {
                        // Add mounted container to our internal housekeeping
                        info!("Mounted {}", container);
                        self.containers.insert(container.clone(), mounted);
                        Ok(container.clone())
                    }
                    Err(e) => {
                        warn!("Failed to mount {}: {}", container, e);
                        Err(e)
                    }
                }
            })
            .collect()
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
                    .map(|f| api::model::Process {
                        pid: f.process.pid(),
                        uptime: f.started.elapsed().as_nanos() as u64,
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

    /// Send a container event to all subriber consoles
    fn container_event(&self, container: &Container, event: ContainerEvent) {
        // Do not fill the notification channel if there's nobody subscribed
        if self.notification_tx.receiver_count() > 0 {
            self.notification_tx.send((container.clone(), event)).ok();
        }
    }

    /// Returns an iterator over the containers currently running
    fn running_containers(&self) -> impl Iterator<Item = &Container> {
        self.containers
            .iter()
            .filter_map(|(container, state)| state.process.is_some().then(|| container))
    }
}
