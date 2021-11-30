use super::{
    cgroups,
    config::{Config, RepositoryType},
    console::Request,
    error::Error,
    mount::{MountControl, MountInfo},
    process::Launcher,
    repository::{DirRepository, MemRepository, Npk},
    stats::ContainerStats,
    Container, ContainerEvent, Event, EventTx, ExitStatus, NotificationTx, Pid, RepositoryId,
};
use crate::{
    api::{self, model},
    common::non_null_string::NonNullString,
    npk::manifest::{Autostart, Manifest, Mount, Resource},
    runtime::{error::Context, CGroupEvent, ENV_NAME, ENV_VERSION},
};
use async_trait::async_trait;
use bytes::Bytes;
use futures::{
    executor::{ThreadPool, ThreadPoolBuilder},
    future::{join_all, ready, Either},
    task::SpawnExt,
    Future, TryFutureExt,
};
use log::{debug, error, info, warn};
use nix::sys::signal::Signal;
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    fmt::Debug,
    iter::FromIterator,
    result,
    sync::Arc,
};
use tokio::{
    sync::{mpsc, oneshot},
    time,
};
use Signal::SIGKILL;

/// Repository
type Repository = Box<dyn super::repository::Repository + Send + Sync>;
/// Container start arguments aka argv
type Args<'a> = Option<&'a Vec<NonNullString>>;
/// Container environment variables set
type Env<'a> = Option<&'a HashMap<NonNullString, NonNullString>>;

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
    mount_control: Arc<MountControl>,
    launcher: Launcher,
    executor: ThreadPool,
    containers: HashMap<Container, ContainerState>,
    repositories: HashMap<RepositoryId, Repository>,
}

#[derive(Debug, Default)]
pub(super) struct ContainerState {
    /// Reference to the repository where the npk resides
    pub repository: RepositoryId,
    /// Meta information about this containers rootfs mount
    pub mount_info: Option<MountInfo>,
    /// Process information when started
    pub process: Option<ProcessContext>,
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
        let repositories = HashMap::new();
        let containers = HashMap::new();
        let mount_control = Arc::new(
            MountControl::new()
                .await
                .expect("Failed to initialize mount control"),
        );
        let launcher = Launcher::start(events_tx.clone(), config.clone(), notification_tx.clone())
            .await
            .expect("Failed to start launcher");

        debug!("Initializing mount thread pool");
        let executor = ThreadPoolBuilder::new()
            .name_prefix("northstar-mount-")
            .pool_size(config.mount_parallel)
            .create()
            .expect("Failed to start mount thread pool");

        let mut state = State {
            events_tx,
            notification_tx,
            repositories,
            containers,
            config,
            launcher,
            mount_control,
            executor,
        };

        // Initialize repositories. This populates self.containers and self.repositories
        state.initialize_repositories().await?;

        // Start containers flagged with autostart
        state.autostart().await?;

        Ok(state)
    }

    /// Iterate the list of repositories and initialize them
    async fn initialize_repositories(&mut self) -> Result<(), Error> {
        // Build a map of repositories from the configuration
        for (id, repository) in &self.config.repositories {
            let repository = match &repository.r#type {
                RepositoryType::Fs { dir } => {
                    let repository = DirRepository::new(dir, repository.key.as_deref()).await?;
                    Box::new(repository) as Repository
                }
                RepositoryType::Memory => {
                    let repository = MemRepository::new(repository.key.as_deref()).await?;
                    Box::new(repository) as Repository
                }
            };
            for npk in repository.containers() {
                let name = npk.manifest().name.clone();
                let version = npk.manifest().version.clone();
                let container = Container::new(name, version);

                if let Ok(state) = self.state(&container) {
                    warn!("Skipping duplicate container {} which is already loaded from repository {}", container, state.repository);
                } else {
                    self.containers.insert(
                        container,
                        ContainerState {
                            repository: id.clone(),
                            ..Default::default()
                        },
                    );
                }
            }
            self.repositories.insert(id.clone(), repository);
        }

        Ok(())
    }

    async fn autostart(&mut self) -> Result<(), Error> {
        // List of containers from all repositories with the autostart flag set
        let mut autostarts = Vec::new();
        for container in self.containers.keys() {
            if let Some(autostart) = self
                .manifest(container)
                .expect("Internal error")
                .autostart
                .as_ref()
            {
                autostarts.push((container.clone(), autostart.clone()))
            }
        }

        // Collect list of mounts to be done before starting the containers
        let mut to_mount = autostarts
            .iter()
            .map(|(c, _)| c.clone())
            .collect::<Vec<_>>();
        // Add resources of containers that have the autostart flag set
        for (container, _) in &autostarts {
            let manifest = self.manifest(container)?;
            for mount in manifest.mounts.values() {
                if let Mount::Resource(Resource { name, version, .. }) = mount {
                    let container = Container::new(name.clone(), version.clone());
                    to_mount.push(container);
                }
            }
        }

        // Mount (parallel). Do not care about the result - this normally is fine. If not, the container will not start.
        if !to_mount.is_empty() {
            self.mount_all(&to_mount).await;

            for (container, autostart) in autostarts {
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
        }

        Ok(())
    }

    /// Create a future that mounts `container`
    fn mount(&self, container: &Container) -> impl Future<Output = Result<MountInfo, Error>> {
        // Find the repository that has the container
        let container_state = self.containers.get(container).expect("Internal error");
        let repository = self
            .repositories
            .get(&container_state.repository)
            .expect("Internal error");
        let key = repository.key().cloned();
        let npk = self.npk(container).expect("Internal error");
        let root = self.config.run_dir.join(container.to_string());
        let mount_control = self.mount_control.clone();
        mount_control
            .mount(npk, &root, key.as_ref())
            .map_err(Error::Mount)
    }

    /// Umount a given container
    #[allow(clippy::blocks_in_if_conditions)]
    async fn umount(&mut self, container: &Container) -> Result<(), Error> {
        let container_state = self.state(container)?;

        info!("Umounting {}", container);
        // Check if the application is started - if yes it cannot be uninstalled
        if container_state.process.is_some() {
            return Err(Error::UmountBusy(container.clone()));
        }

        let manifest = self.manifest(container).unwrap();

        // If this container is a resource check all runing containers if they
        // depend on `container`
        if manifest.init.is_none() {
            for (c, state) in &self.containers {
                // A not started container cannot use `container`
                if state.process.is_none() {
                    continue;
                }

                // Get manifest for container in question
                let manifest = self.manifest(c).expect("Internal error");

                // Resources cannot have resource dependencies
                if manifest.init.is_none() {
                    continue;
                }

                for mount in &manifest.mounts {
                    if let Mount::Resource(Resource { name, version, .. }) = mount.1 {
                        if container.name() == name && container.version() == version {
                            warn!(
                                "Failed to umount busy resource container {}. Used by {}",
                                container, c
                            );
                            return Err(Error::UmountBusy(container.clone()));
                        }
                    }
                }
            }
        }

        if let Some(mount_info) = &container_state.mount_info {
            self.mount_control
                .umount(mount_info)
                .await
                .map_err(Error::Mount)?;
        } else {
            warn!("Container {} is not mounted", container);
            return Err(Error::UmountBusy(container.clone()));
        }

        let container_state = self.state_mut(container).expect("Internal error");
        container_state.mount_info.take();
        Ok(())
    }

    /// Start a container
    /// `container`: Container to start
    /// `args`: Optional command line arguments that overwrite the values from the manifest
    /// `env`: Optional env variables that overwrite the values from the manifest
    pub(super) async fn start(
        &mut self,
        container: &Container,
        args: Args<'_>,
        env: Env<'_>,
    ) -> Result<(), Error> {
        let start = time::Instant::now();
        info!("Trying to start {}", container);

        // Check if the container is already running
        let container_state = self.state(container)?;
        if container_state.process.is_some() {
            warn!("Application {} is already running", container);
            return Err(Error::StartContainerStarted(container.clone()));
        }

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

        let manifest = self.manifest(container)?.clone();

        // Check if the container is not a resource
        if manifest.init.is_none() {
            warn!("Container {} is a resource", container);
            return Err(Error::StartContainerResource(container.clone()));
        }

        let mut need_mount = HashSet::new();

        // The container to be started
        if container_state.mount_info.is_none() {
            need_mount.insert(container.clone());
        }

        // Collect resources used by container
        let resources = manifest
            .mounts
            .values()
            .filter_map(|m| match m {
                Mount::Resource(Resource { name, version, .. }) => {
                    Some(Container::new(name.clone(), version.clone()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        // Check if all resources are available
        for resource in &resources {
            if !self.containers.contains_key(resource) {
                return Err(Error::StartContainerMissingResource(
                    container.clone(),
                    resource.clone(),
                ));
            }
        }

        // Add resources to the mount vector
        for resource in resources {
            let resource_state = self.state(&resource).expect("Internal error");
            if resource_state.mount_info.is_none() {
                need_mount.insert(resource.clone());
            }
        }

        // Mount containers
        if !need_mount.is_empty() {
            info!(
                "Mounting {} container(s) for the start of {}",
                need_mount.len(),
                container
            );
            for mount in self.mount_all(&Vec::from_iter(need_mount)).await {
                // Abort if at least one container failed to mount
                if let Err(e) = mount {
                    warn!("Failed to mount: {}", e);
                    return Err(e);
                }
            }
        }

        // Get a mutable reference to the container state in order to update the process field
        let container_state = self.containers.get_mut(container).expect("Internal error");

        // Root of container
        let root = container_state
            .mount_info
            .as_ref()
            .and_then(|m| m.target.canonicalize().ok())
            .expect("Failed to canonicalize root");

        // Spawn process
        info!("Creating {}", container);

        let mut process = match self
            .launcher
            .create(&root, container, &manifest, args, env)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to create process for {}", container);
                return Err(e);
            }
        };

        let pid = process.pid();

        // Debug
        let debug = super::debug::Debug::new(self.config, &manifest, pid).await?;

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
                process.pid(),
            )
            .await
            .expect("Failed to create cgroup")
        };

        // Signal the process to continue starting. This can fail because of the container content
        if let Err(e) = process.spawn().await {
            warn!("Failed to start {} ({}): {}", container, pid, e);
            debug.destroy().await.expect("Failed to destroy debug");
            cgroups.destroy().await;
            return Err(e);
        }

        // Add process context to process
        container_state.process = Some(ProcessContext {
            process: Box::new(process),
            started: time::Instant::now(),
            debug,
            cgroups,
        });

        let duration = start.elapsed().as_secs_f32();
        info!("Started {} ({}) in {:.03}s", container, pid, duration);

        // Send container started event
        self.container_event(container, ContainerEvent::Started);

        Ok(())
    }

    /// Send signal `signal` to container if running
    pub(super) async fn kill(
        &mut self,
        container: &Container,
        signal: Signal,
    ) -> Result<(), Error> {
        let container_state = self.state_mut(container)?;

        match &mut container_state.process {
            Some(process) => {
                info!("Killing {} with {}", container, signal.as_str());
                process.kill(signal).await
            }
            None => Err(Error::StopContainerNotStarted(container.clone())),
        }
    }

    /// Shutdown the runtime: stop running applications and umount npks
    pub(super) async fn shutdown(mut self) -> Result<(), Error> {
        let to_umount = self
            .containers
            .iter()
            .filter_map(|(container, state)| state.mount_info.as_ref().map(|_| container.clone()))
            .collect::<Vec<_>>();

        for (container, state) in &mut self.containers {
            if let Some(mut context) = state.process.take() {
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

        for container in to_umount {
            self.umount(&container).await?;
        }

        self.launcher.shutdown().await?;

        Ok(())
    }

    /// Install an NPK
    async fn install(&mut self, id: &str, rx: &mut mpsc::Receiver<Bytes>) -> Result<(), Error> {
        // Find the repository
        let repository = self
            .repositories
            .get_mut(id)
            .ok_or_else(|| Error::InvalidRepository(id.to_string()))?;

        // Add the npk to the repository
        let container = repository.insert(rx).await?;

        // Check if container is already known and remove newly installed one if so
        if let Ok(state) = self.state(&container) {
            warn!(
                "Skipping duplicate container {} which is already in repository {}",
                container, state.repository
            );
            let repository = self
                .repositories
                .get_mut(id)
                .ok_or_else(|| Error::InvalidRepository(id.to_string()))?;
            repository.remove(&container).await?;
            Err(Error::InstallDuplicate(container))
        } else {
            // Add the container to the state
            self.containers.insert(
                container.clone(),
                ContainerState {
                    repository: id.into(),
                    ..Default::default()
                },
            );
            info!("Successfully installed {}", container);

            self.container_event(&container, ContainerEvent::Installed);

            Ok(())
        }
    }

    /// Remove and umount a specific app
    #[allow(clippy::blocks_in_if_conditions)]
    async fn uninstall(&mut self, container: &Container) -> result::Result<(), Error> {
        info!("Trying to uninstall {}", container);

        let state = self.state(container)?;
        let is_mounted = state.mount_info.is_some();
        let repository = state.repository.clone();

        // Umount
        if is_mounted {
            self.umount(container).await?;
        }

        // Remove from repository
        debug!("Removing {} from {}", container, repository);
        self.repositories
            .get_mut(&repository)
            .expect("Internal error")
            .remove(container)
            .await?;

        self.containers.remove(container);
        info!("Successfully uninstalled {}", container);

        self.container_event(container, ContainerEvent::Uninstalled);

        Ok(())
    }

    /// Gather statistics for `container`
    async fn container_stats(
        &mut self,
        container: &Container,
    ) -> result::Result<ContainerStats, Error> {
        // Get container state or return if it's unknown
        let state = self.state(container)?;

        // Gather stats if the container is running
        if let Some(process) = state.process.as_ref() {
            info!("Collecting stats of {}", container);
            Ok(process.cgroups.stats())
        } else {
            Err(Error::ContainerNotStarted(container.clone()))
        }
    }

    /// Handle the exit of a container
    async fn on_exit(
        &mut self,
        container: &Container,
        exit_status: &ExitStatus,
    ) -> Result<(), Error> {
        let autostart = self
            .manifest(container)
            .ok()
            .and_then(|manfiest| manfiest.autostart.clone());

        if let Ok(state) = self.state_mut(container) {
            if let Some(process) = state.process.take() {
                let is_critical = autostart == Some(Autostart::Critical);
                let duration = process.started.elapsed();
                if is_critical {
                    error!(
                        "Critical process {} exited after {:?} with status {}",
                        container, duration, exit_status,
                    );
                } else {
                    info!(
                        "Process {} exited after {:?} with status {}",
                        container, duration, exit_status,
                    );
                }

                process.destroy().await;

                self.container_event(container, ContainerEvent::Exit(exit_status.clone()));

                // This is a critical flagged container that exited with a error exit code. That's not good...
                if !exit_status.success() && is_critical {
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
                if let api::model::Message::Request { ref request } = message {
                    let response = match request {
                        api::model::Request::Containers => model::Response::Containers {
                            containers: self.list_containers(),
                        },
                        api::model::Request::Install { .. } => unreachable!(),
                        api::model::Request::Mount { containers } => {
                            let result = self
                                .mount_all(containers)
                                .await
                                .drain(..)
                                .zip(containers)
                                .map(|(r, c)| match r {
                                    Ok(r) => model::MountResult::Ok { container: r },
                                    Err(e) => model::MountResult::Error {
                                        container: c.clone(),
                                        error: e.into(),
                                    },
                                })
                                .collect();
                            model::Response::Mount { result }
                        }
                        api::model::Request::Repositories => {
                            let repositories = self.repositories.keys().cloned().collect();
                            model::Response::Repositories { repositories }
                        }
                        api::model::Request::Shutdown => {
                            self.events_tx
                                .send(Event::Shutdown)
                                .await
                                .expect("Internal channel error on main");
                            model::Response::Ok
                        }
                        api::model::Request::Start {
                            container,
                            args,
                            env,
                        } => match self.start(container, args.as_ref(), env.as_ref()).await {
                            Ok(_) => model::Response::Ok,
                            Err(e) => {
                                warn!("Failed to start {}: {}", container, e);
                                model::Response::Error { error: e.into() }
                            }
                        },
                        api::model::Request::Kill { container, signal } => {
                            let signal = Signal::try_from(*signal).unwrap();
                            match self.kill(container, signal).await {
                                Ok(_) => model::Response::Ok,
                                Err(e) => {
                                    error!("Failed to kill {} with {}: {}", container, signal, e);
                                    model::Response::Error { error: e.into() }
                                }
                            }
                        }
                        api::model::Request::Umount { container } => {
                            match self.umount(container).await {
                                Ok(_) => api::model::Response::Ok,
                                Err(e) => {
                                    warn!("Failed to unmount{}: {}", container, e);
                                    model::Response::Error { error: e.into() }
                                }
                            }
                        }
                        api::model::Request::Uninstall { container } => {
                            match self.uninstall(container).await {
                                Ok(_) => api::model::Response::Ok,
                                Err(e) => {
                                    warn!("Failed to uninstall {}: {}", container, e);
                                    model::Response::Error { error: e.into() }
                                }
                            }
                        }
                        api::model::Request::ContainerStats { container } => {
                            match self.container_stats(container).await {
                                Ok(stats) => api::model::Response::ContainerStats {
                                    container: container.clone(),
                                    stats,
                                },
                                Err(e) => {
                                    warn!("Failed to gather stats for {}: {}", container, e);
                                    model::Response::Error { error: e.into() }
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
                    Ok(_) => model::Response::Ok,
                    Err(e) => model::Response::Error { error: e.into() },
                };

                // A error on the response_tx means that the connection
                // was closed in the meantime. Ignore it.
                response_tx.send(payload).ok();
            }
        }
        Ok(())
    }

    /// Try to mount all containers in `containers` in parallel and return the results. The parallelism
    /// is archived by a dedicated thread pool that exectures the blocking mount operations on n threads
    /// as configured in the runtime configuration.
    async fn mount_all(&mut self, containers: &[Container]) -> Vec<Result<Container, Error>> {
        let start = time::Instant::now();
        let mut mounts = Vec::with_capacity(containers.len());

        // Create mount futures
        for c in containers {
            // Containers cannot be mounted twice
            if self
                .containers
                .get(c)
                .map(|s| s.mount_info.is_some())
                .unwrap_or(false)
            {
                let error = Err(Error::MountBusy(c.clone()));
                mounts.push(Either::Right(ready(error)));
            } else {
                mounts.push(Either::Left(self.mount(c)))
            }
        }

        // Spawn mount tasks onto the executor
        let mounts = mounts
            .drain(..)
            .map(|t| self.executor.spawn_with_handle(t).unwrap());

        // Process mount results
        let mut result = Vec::new();
        for (container, mount_result) in containers.iter().zip(join_all(mounts).await) {
            match mount_result {
                Ok(mount_info) => {
                    let container_state = self.state_mut(container).expect("Internal error");
                    container_state.mount_info = Some(mount_info);
                    info!("Mounted {}", container);
                    result.push(Ok(container.clone()));
                }
                Err(e) => {
                    warn!("Failed to mount {}: {:#?}", container, e);
                    result.push(Err(e));
                }
            }
        }
        let duration = start.elapsed().as_secs_f32();
        if result.iter().any(|e| e.is_err()) {
            warn!("Mount operation failed after {:.03}s", duration);
        } else {
            info!(
                "Successfully {} container(s) in {:.03}s",
                result.len(),
                duration
            );
        }
        result
    }

    fn list_containers(&self) -> Vec<api::model::ContainerData> {
        let mut result = Vec::with_capacity(self.containers.len());

        for (container, state) in &self.containers {
            let manifest = self.manifest(container).expect("Internal error").clone();
            let process = state.process.as_ref().map(|context| api::model::Process {
                pid: context.process.pid(),
                uptime: context.started.elapsed().as_nanos() as u64,
            });
            let repository = state.repository.clone();
            let mounted = state.mount_info.is_some();
            let container_data = api::model::ContainerData::new(
                container.clone(),
                repository,
                manifest,
                process,
                mounted,
            );
            result.push(container_data);
        }

        result
    }

    /// Send a container event to all subriber consoles
    fn container_event(&self, container: &Container, event: ContainerEvent) {
        // Do not fill the notification channel if there's nobody subscribed
        if self.notification_tx.receiver_count() > 0 {
            self.notification_tx.send((container.clone(), event)).ok();
        }
    }

    fn state(&self, container: &Container) -> Result<&ContainerState, Error> {
        self.containers
            .get(container)
            .ok_or_else(|| Error::InvalidContainer(container.clone()))
    }

    fn state_mut(&mut self, container: &Container) -> Result<&mut ContainerState, Error> {
        self.containers
            .get_mut(container)
            .ok_or_else(|| Error::InvalidContainer(container.clone()))
    }

    fn npk(&self, container: &Container) -> Result<&Npk, Error> {
        let state = self.state(container)?;
        let repository = self.repository(&state.repository)?;
        repository
            .get(container)
            .ok_or_else(|| Error::InvalidContainer(container.clone()))
    }

    fn manifest(&self, container: &Container) -> Result<&Manifest, Error> {
        let npk = self.npk(container)?;
        Ok(npk.manifest())
    }

    fn repository(&self, repository: &str) -> Result<&Repository, Error> {
        self.repositories
            .get(repository)
            .ok_or_else(|| Error::InvalidRepository(repository.into()))
    }
}
