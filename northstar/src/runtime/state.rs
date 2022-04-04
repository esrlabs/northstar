use super::{
    cgroups,
    config::{Config, RepositoryType},
    console::Request,
    error::Error,
    fork::Forker,
    io,
    mount::MountControl,
    repository::{DirRepository, MemRepository, Npk},
    stats::ContainerStats,
    Container, ContainerEvent, Event, EventTx, ExitStatus, NotificationTx, Pid, RepositoryId,
};
use crate::{
    api::{self, model},
    common::non_null_string::NonNullString,
    npk::manifest::{Autostart, Manifest, Mount, Resource},
    runtime::{
        console::{Console, Peer},
        io::ContainerIo,
        ipc::owned_fd::OwnedFd,
        CGroupEvent, ENV_CONSOLE, ENV_CONTAINER, ENV_NAME, ENV_VERSION,
    },
};
use bytes::Bytes;
use derive_new::new;
use futures::{
    future::{join_all, ready, Either},
    Future, FutureExt, Stream, StreamExt, TryFutureExt,
};
use humantime::format_duration;
use itertools::Itertools;
use log::{debug, error, info, warn};
use nix::sys::signal::Signal;
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    fmt::Debug,
    iter::{once, FromIterator},
    os::unix::net::UnixStream as StdUnixStream,
    path::PathBuf,
    result,
    sync::Arc,
};
use tokio::{
    net::UnixStream,
    pin,
    sync::{mpsc, oneshot},
    task::{self, JoinHandle},
    time,
};
use tokio_util::sync::CancellationToken;

/// Repository
type Repository = Box<dyn super::repository::Repository + Send + Sync>;
/// Container start arguments aka argv
type Args<'a> = Option<&'a Vec<NonNullString>>;
/// Container environment variables set
type Env<'a> = Option<&'a HashMap<NonNullString, NonNullString>>;

#[derive(Debug)]
pub(super) struct State {
    config: Config,
    events_tx: EventTx,
    notification_tx: NotificationTx,
    mount_control: Arc<MountControl>,
    launcher: Forker,
    containers: HashMap<Container, ContainerState>,
    repositories: HashMap<RepositoryId, Repository>,
}

#[derive(Debug, Default)]
pub(super) struct ContainerState {
    /// Reference to the repository where the npk resides
    pub repository: RepositoryId,
    /// Mount point of the root fs
    pub root: Option<PathBuf>,
    /// Process information when started
    pub process: Option<ContainerContext>,
}

impl ContainerState {
    pub fn is_mounted(&self) -> bool {
        self.root.is_some()
    }
}

#[derive(new, Debug)]
pub(super) struct ContainerContext {
    pid: Pid,
    started: time::Instant,
    debug: super::debug::Debug,
    cgroups: cgroups::CGroups,
    stop: CancellationToken,
    log_task: Option<JoinHandle<std::io::Result<()>>>,
}

impl ContainerContext {
    async fn destroy(mut self) {
        // Stop console if there's any any
        self.stop.cancel();

        if let Some(log_task) = self.log_task.take() {
            // Wait for the pty to finish
            drop(log_task.await);
        }

        self.debug
            .destroy()
            .await
            .expect("Failed to destroy debug utilities");

        self.cgroups.destroy().await;
    }
}

impl State {
    /// Create a new empty State instance
    pub(super) async fn new(
        config: Config,
        events_tx: EventTx,
        notification_tx: NotificationTx,
        forker: Forker,
    ) -> Result<State, Error> {
        let repositories = HashMap::new();
        let containers = HashMap::new();
        let mount_control = Arc::new(
            MountControl::new()
                .await
                .expect("Failed to initialize mount control"),
        );

        let mut state = State {
            events_tx,
            notification_tx,
            repositories,
            containers,
            config,
            launcher: forker,
            mount_control,
        };

        // Initialize repositories. This populates self.containers and self.repositories
        let mount_repositories = state.initialize_repositories().await?;

        // Mount all containers if configured
        state.automount(&mount_repositories).await?;

        // Start containers flagged with autostart
        state.autostart().await?;

        Ok(state)
    }

    /// Iterate the list of repositories and initialize them
    async fn initialize_repositories(&mut self) -> Result<HashSet<RepositoryId>, Error> {
        // List of repositories to mount
        let mut mount_repositories = HashSet::with_capacity(self.config.repositories.len());

        // Build a map of repositories from the configuration
        for (id, repository) in &self.config.repositories {
            if repository.mount_on_start {
                mount_repositories.insert(id.clone());
            }

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

        Ok(mount_repositories)
    }

    /// Try to mount all installed continers
    async fn automount(&mut self, repositories: &HashSet<RepositoryId>) -> Result<(), Error> {
        if repositories.is_empty() {
            return Ok(());
        }

        info!(
            "Trying to mount containers from repository {}",
            repositories.iter().join(", ")
        );
        // Collect all containers that match a repository in `repositories
        let containers = self
            .containers
            .iter()
            .filter(|(_, state)| repositories.contains(&state.repository))
            .map(|(container, _)| container.clone())
            .collect::<Vec<Container>>();

        if !containers.is_empty() {
            for result in self.mount_all(&containers).await {
                result?;
            }
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
            .filter(|(c, _)| !self.state(c).unwrap().is_mounted()) // safe - list from above
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
    fn mount(&self, container: &Container) -> impl Future<Output = Result<PathBuf, Error>> {
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
            .map(|_| Ok(root))
    }

    /// Create a future that umounts `container`. Return a futures that yield
    /// a busy error if the container is not mounted.
    fn umount(&self, container: &Container) -> impl Future<Output = Result<(), Error>> {
        match self.state(container).and_then(|state| {
            state
                .root
                .as_ref()
                .ok_or_else(|| Error::UmountBusy(container.clone()))
        }) {
            Ok(root) => Either::Left(MountControl::umount(root).map_err(Error::Mount)),
            Err(e) => Either::Right(ready(Err(e))),
        }
    }

    /// Start a container
    /// `container`: Container to start
    /// `args_extra`: Optional command line arguments that overwrite the values from the manifest
    /// `env_extra`: Optional env variables that overwrite the values from the manifest
    pub(super) async fn start(
        &mut self,
        container: &Container,
        args_extra: Args<'_>,
        env_extra: Env<'_>,
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
        if let Some(env) = env_extra {
            if env.keys().any(|k| {
                k.as_str() == ENV_NAME
                    || k.as_str() == ENV_VERSION
                    || k.as_str() == ENV_CONTAINER
                    || k.as_str() == ENV_CONSOLE
            }) {
                return Err(Error::InvalidArguments(format!(
                    "env contains reserved key {} or {} or {} or {}",
                    ENV_NAME, ENV_VERSION, ENV_CONTAINER, ENV_CONSOLE
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
        if !container_state.is_mounted() {
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
            if !resource_state.is_mounted() {
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

        // Spawn process
        info!("Creating {}", container);

        // Create a token to stop tasks spawned related to this container
        let stop = CancellationToken::new();

        // We send the fd to the forker so that it can pass it to the init
        let console_fd = if !manifest.console.is_empty() {
            let peer = Peer::from(container.to_string());
            let (runtime_stream, container_stream) =
                StdUnixStream::pair().expect("Failed to create socketpair");
            let container_fd: OwnedFd = container_stream.into();

            let runtime = runtime_stream
                .set_nonblocking(true)
                .and_then(|_| UnixStream::from_std(runtime_stream))
                .expect("Failed to set socket into nonblocking mode");

            let notifications = self.notification_tx.subscribe();
            let events_tx = self.events_tx.clone();
            let stop = stop.clone();
            let container = Some(container.clone());
            let permissions = manifest.console.clone();
            let connection = Console::connection(
                runtime,
                peer,
                stop,
                container,
                permissions,
                events_tx,
                notifications,
                None,
            );

            // Start console task
            task::spawn(connection);

            Some(container_fd)
        } else {
            None
        };

        // Create container
        let config = &self.config;
        let pid = self.launcher.create(config, &manifest, console_fd).await?;

        // Debug
        let debug = super::debug::Debug::new(&self.config, &manifest, pid).await?;

        // CGroups
        let cgroups = {
            let config = manifest.cgroups.clone().unwrap_or_default();
            let events_tx = self.events_tx.clone();

            // Creating a cgroup is a northstar internal thing. If it fails it's not recoverable.
            cgroups::CGroups::new(&self.config.cgroup, events_tx, container, &config, pid)
                .await
                .expect("Failed to create cgroup")
        };

        // Open a file handle for stdin, stdout and stderr according to the manifest
        let ContainerIo { io, log_task } = io::open(container, &manifest.io)
            .await
            .expect("IO setup error");

        let path = manifest.init.unwrap();
        let mut args = vec![path.display().to_string()];
        if let Some(extra_args) = args_extra {
            args.extend(extra_args.iter().map(ToString::to_string));
        } else if let Some(manifest_args) = manifest.args {
            args.extend(manifest_args.iter().map(ToString::to_string));
        };

        // Prepare the environment for the container according to the manifest
        let env = match (env_extra, &manifest.env) {
            (Some(env), _) => env.clone(),
            (None, Some(env)) => env.clone(),
            (None, None) => HashMap::with_capacity(3),
        };
        let env = env
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .chain(once(format!("{}={}", ENV_CONTAINER, container)))
            .chain(once(format!("{}={}", ENV_NAME, container.name())))
            .chain(once(format!("{}={}", ENV_VERSION, container.version())))
            .collect::<Vec<_>>();

        debug!("Container {} init is {:?}", container, path.display());
        debug!("Container {} argv is {}", container, args.iter().join(" "));
        debug!("Container {} env is {}", container, env.iter().join(", "));

        // Send exec request to launcher
        if let Err(e) = self
            .launcher
            .exec(container.clone(), path, args, dbg!(env), io)
            .await
        {
            warn!("Failed to exec {} ({}): {}", container, pid, e);

            stop.cancel();

            if let Some(log_task) = log_task {
                drop(log_task.await);
            }
            debug.destroy().await.expect("Failed to destroy debug");
            cgroups.destroy().await;
            return Err(e);
        }

        // Add process context to process
        let started = time::Instant::now();
        let context = ContainerContext::new(pid, started, debug, cgroups, stop, log_task);
        container_state.process = Some(context);

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
            Some(context) => {
                info!("Killing {} with {}", container, signal.as_str());
                let pid = context.pid;
                let process_group = nix::unistd::Pid::from_raw(-(pid as i32));
                match nix::sys::signal::kill(process_group, Some(signal)) {
                    Ok(_) => Ok(()),
                    Err(nix::Error::ESRCH) => {
                        debug!("Process {} already exited", pid);
                        Ok(())
                    }
                    Err(e) => unimplemented!("Kill error {}", e),
                }
            }
            None => Err(Error::StopContainerNotStarted(container.clone())),
        }
    }

    /// Shutdown the runtime: stop running applications and umount npks
    pub(super) async fn shutdown(
        mut self,
        event_rx: impl Stream<Item = Event>,
    ) -> Result<(), Error> {
        let started_containers = self
            .containers
            .iter()
            .filter_map(|(container, state)| state.process.as_ref().map(|_| container.clone()))
            .collect::<Vec<_>>();

        // Send a SIGKILL to each started container
        for container in &started_containers {
            self.kill(container, Signal::SIGKILL).await?;
        }

        // Wait until all processes are gone
        pin!(event_rx);
        while self
            .containers
            .values()
            .any(|state| state.process.is_some())
        {
            if let Some(Event::Container(container, event)) = event_rx.next().await {
                self.on_event(&container, &event, true).await?;
            }
        }

        // Try to umount mounted containers
        let to_umount = self
            .containers
            .iter()
            .filter(|(_, state)| state.is_mounted())
            .map(|(container, _)| container.clone())
            .collect::<Vec<_>>();
        self.umount_all(&to_umount).await;

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
        let already_installed = self
            .state(&container)
            .ok()
            .map(|state| state.repository.clone());

        if let Some(current_repository) = already_installed {
            warn!(
                "Skipping duplicate container {} which is already in repository {}",
                container, current_repository
            );

            let repository = self
                .repositories
                .get_mut(id)
                .ok_or_else(|| Error::InvalidRepository(id.to_string()))?;
            repository.remove(&container).await?;
            return Err(Error::InstallDuplicate(container));
        }

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

    /// Remove and umount a specific app
    async fn uninstall(&mut self, container: &Container) -> Result<(), Error> {
        info!("Trying to uninstall {}", container);

        let state = self.state(container)?;
        let repository = state.repository.clone();

        // Umount
        if state.is_mounted() {
            self.umount_all(&[container.clone()]).await.pop().unwrap()?;
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
        is_shutdown: bool,
    ) -> Result<(), Error> {
        let autostart = self
            .manifest(container)
            .ok()
            .and_then(|manfiest| manfiest.autostart.clone());

        if let Ok(state) = self.state_mut(container) {
            if let Some(process) = state.process.take() {
                let is_critical = autostart == Some(Autostart::Critical);
                let is_critical = is_critical && !is_shutdown;
                let duration = process.started.elapsed();
                if is_critical {
                    error!(
                        "Critical process {} exited after {} with status {}",
                        container,
                        format_duration(duration),
                        exit_status,
                    );
                } else {
                    info!(
                        "Process {} exited after {} with status {}",
                        container,
                        format_duration(duration),
                        exit_status,
                    );
                }

                process.destroy().await;

                self.container_event(container, ContainerEvent::Exit(exit_status.clone()));

                info!("Container {} exited with status {}", container, exit_status);

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
        is_shutdown: bool,
    ) -> Result<(), Error> {
        match event {
            ContainerEvent::Started => (),
            ContainerEvent::Exit(exit_status) => {
                self.on_exit(container, exit_status, is_shutdown).await?;
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
        repsponse: oneshot::Sender<api::model::Response>,
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
                        api::model::Request::Umount { containers } => {
                            let result = self
                                .umount_all(containers)
                                .await
                                .drain(..)
                                .zip(containers)
                                .map(|(r, c)| match r {
                                    Ok(r) => model::UmountResult::Ok { container: r },
                                    Err(e) => model::UmountResult::Error {
                                        container: c.clone(),
                                        error: e.into(),
                                    },
                                })
                                .collect();
                            model::Response::Umount { result }
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
                        } => {
                            let args = (!args.is_empty()).then(|| args);
                            let env = (!env.is_empty()).then(|| env);
                            match self.start(container, args, env).await {
                                Ok(_) => model::Response::Ok,
                                Err(e) => {
                                    warn!("Failed to start {}: {}", container, e);
                                    model::Response::Error { error: e.into() }
                                }
                            }
                        }
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
                    repsponse.send(response).ok();
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
                repsponse.send(payload).ok();
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
        for container in containers {
            // Containers cannot be mounted twice. If the container
            // is already mounted return an error for this entity.
            let is_mounted = self
                .state(container)
                .map(|s| s.is_mounted())
                .unwrap_or(false);
            if is_mounted {
                let error = Err(Error::MountBusy(container.clone()));
                mounts.push(Either::Right(ready(error)));
            } else {
                mounts.push(Either::Left(self.mount(container)))
            }
        }

        // Mount and process results
        let mut result = Vec::with_capacity(containers.len());
        for (container, mount_result) in containers.iter().zip(join_all(mounts).await) {
            match mount_result {
                Ok(root) => {
                    let state = self.state_mut(container).expect("Internal error");
                    state.root = Some(root);
                    info!("Mounted {}", container);
                    result.push(Ok(container.clone()));
                }
                Err(e) => {
                    warn!("Failed to mount {}: {}", container, e);
                    result.push(Err(e));
                }
            }
        }

        let duration = start.elapsed();
        if result.iter().any(|e| e.is_err()) {
            warn!("Mount operation failed after {}", format_duration(duration));
        } else {
            info!(
                "Successfully mounted {} container(s) in {}",
                result.len(),
                format_duration(duration)
            );
        }
        result
    }

    async fn umount_all(&mut self, containers: &[Container]) -> Vec<Result<Container, Error>> {
        let start = time::Instant::now();
        let mut mounts = Vec::with_capacity(containers.len());

        // Create mount futures
        'outer: for container in containers {
            // Retrieve container state. If the container is unknown insert a
            // ready future with the corresponding error
            let container_state = if let Ok(state) = self.state(container) {
                state
            } else {
                let error = Err(Error::InvalidContainer(container.clone()));
                mounts.push(Either::Right(ready(error)));
                continue;
            };

            // Check if container is mounted at all
            if !container_state.is_mounted() {
                let error = Err(Error::MountBusy(container.clone()));
                mounts.push(Either::Right(ready(error)));
                continue;
            }

            // Check if container is started
            if container_state.process.is_some() {
                let error = Err(Error::MountBusy(container.clone()));
                mounts.push(Either::Right(ready(error)));
                continue;
            }

            let manifest = self.manifest(container).unwrap(); // safe - checked above

            // If this container is a resource check all running containers if they
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
                                warn!("Resource container {} is used by {}", container, c);
                                let error = Err(Error::MountBusy(c.clone()));
                                mounts.push(Either::Right(ready(error)));
                                continue 'outer;
                            }
                        }
                    }
                }
            }

            // Hm. Seems that it really needs to be umounted.
            mounts.push(Either::Left(self.umount(container)));
        }

        debug_assert_eq!(mounts.len(), containers.len());

        // Umount and process umount results
        let mut result = Vec::with_capacity(containers.len());
        for (container, mount_result) in containers.iter().zip(join_all(mounts).await) {
            match mount_result {
                Ok(_) => {
                    let state = self.state_mut(container).expect("Internal error");
                    state.root = None;
                    info!("Umounted {}", container);
                    result.push(Ok(container.clone()));
                }
                Err(e) => {
                    warn!("Failed to mount {}: {}", container, e);
                    result.push(Err(e));
                }
            }
        }

        let duration = start.elapsed();
        if result.iter().any(|e| e.is_err()) {
            warn!(
                "Umount operation failed after {}",
                format_duration(duration)
            );
        } else {
            info!(
                "Successfully umounted {} container(s) in {}",
                result.len(),
                format_duration(duration)
            );
        }
        result
    }

    fn list_containers(&self) -> Vec<api::model::ContainerData> {
        let mut result = Vec::with_capacity(self.containers.len());

        for (container, state) in &self.containers {
            let manifest = self.manifest(container).expect("Internal error").clone();
            let process = state.process.as_ref().map(|context| api::model::Process {
                pid: context.pid,
                uptime: context.started.elapsed().as_nanos() as u64,
            });
            let repository = state.repository.clone();
            let is_mounted = state.is_mounted();
            let container_data = api::model::ContainerData::new(
                container.clone(),
                repository,
                manifest,
                process,
                is_mounted,
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
