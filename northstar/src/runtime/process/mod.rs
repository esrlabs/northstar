use std::{
    collections::HashMap,
    ffi::{c_void, CString},
    fmt,
    mem::forget,
    os::unix::{
        net::UnixStream as StdUnixStream,
        prelude::{AsRawFd, FromRawFd},
    },
    path::Path,
    ptr::null,
};

use async_trait::async_trait;
use futures::{Future, TryFutureExt};
use log::{debug, error, warn};
use nix::{
    errno::Errno,
    sys::{self, signal::Signal, socket},
    unistd,
};
use sys::wait;
use tokio::{net::UnixStream, task, time};
use tokio_util::sync::CancellationToken;

use crate::{
    common::{container::Container, non_null_string::NonNullString},
    npk::manifest::Manifest,
    runtime::{
        config::Config,
        console::{self, Peer},
        error::{Context, Error},
        ipc::channel,
        process::{fork::fork, init::InitMessage},
        ContainerEvent, Event, EventTx, ExitStatus, NotificationTx, Pid, ENV_NAME, ENV_VERSION,
    },
    seccomp,
};

use self::init::Exec;

mod fork;
mod fs;
mod init;
mod io;

#[derive(Debug)]
pub(super) struct Launcher {
    tx: EventTx,
    notification_tx: NotificationTx,
    config: Config,
}

pub(super) struct Process {
    init_tx: channel::AsyncSender<Exec>,
    init_rx: Option<channel::AsyncReceiver<InitMessage>>,
    console_stop: Option<CancellationToken>,
    container: Container,
    exit_status: Option<Box<dyn Future<Output = ExitStatus> + Send + Sync + Unpin>>,
    pid: Pid,
    tx: EventTx,
    path: CString,
    args: Vec<CString>,
    env: Vec<CString>,
}

impl fmt::Debug for Process {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Process")
            .field("pid", &self.pid)
            .field("container", &self.container)
            .field("path", &self.path)
            .field("args", &self.args)
            .field("env", &self.env)
            .finish()
    }
}

impl Launcher {
    pub async fn start(
        tx: EventTx,
        config: Config,
        notification_tx: NotificationTx,
    ) -> Result<Self, Error> {
        set_child_subreaper(true)?;

        let launcher = Launcher {
            tx,
            config,
            notification_tx,
        };

        Ok(launcher)
    }

    pub async fn shutdown(self) -> Result<(), Error> {
        Ok(())
    }

    /// Create a new container process set
    pub async fn create(
        &self,
        root: &Path,
        container: &Container,
        manifest: &Manifest,
        args: Option<&Vec<NonNullString>>,
        env: Option<&HashMap<NonNullString, NonNullString>>,
    ) -> Result<impl super::state::Process, Error> {
        // Token to stop the console task if any. This token is cancelled when
        // the waitpid of this child process signals that the child is exited. See
        // `wait`.
        let stop = CancellationToken::new();
        let (cmd, argv) = init_argv(manifest, args);
        let mut env = self::env(manifest, env);

        // Setup io and collect fd setup set
        let (io, mut fds) = io::from_manifest(manifest).await?;

        // Two-way communication channels with the init process.
        let mut pipe_to_init = channel::Channel::<Exec>::new();
        let mut pipe_from_init = channel::Channel::<InitMessage>::new();

        // Setup console if configured
        let console_fd = console_fd(
            self.tx.clone(),
            manifest,
            &mut env,
            &mut fds,
            stop.clone(),
            &self.notification_tx,
        )
        .await;

        let capabilities = manifest.capabilities.clone();
        let fds = fds.drain().collect::<Vec<_>>();
        let uid = manifest.uid;
        let gid = manifest.gid;
        let groups = groups(manifest);
        let mounts = fs::prepare_mounts(&self.config, root, manifest).await?;
        let rlimits = manifest.rlimits.clone();
        let root = root.to_owned();
        let seccomp = seccomp_filter(manifest);

        debug!("{} init is {:?}", container, cmd);
        debug!("{} argv is {:?}", container, argv);
        debug!("{} env is {:?}", container, env);

        let init = init::Init {
            root,
            uid,
            gid,
            mounts,
            fds,
            groups,
            capabilities,
            rlimits,
            seccomp,
        };

        // Channel just for receiving the init pid from the intermediate process
        let mut init_pid_channel = channel::Channel::<u32>::new();

        let trampoline_pid = fork(|| {
            // FIXME After this point the tokio runtime is in a kind of undefined state :(

            // Forget writing ends of io which are stdout, stderr. The `forget`
            // ensures that the file descriptors are not closed
            forget(io);

            let mut init_pid_tx = init_pid_channel.write_end();

            // Keep init's relevant ends from each channel
            let init_rx = pipe_to_init.read_end();
            let init_tx = pipe_from_init.write_end();

            // Create pid namespace
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWPID)
                .expect("Failed to create pid namespace");

            // Fork the init process
            let init_pid = fork(|| {
                // Dive into init and never return
                init.run(init_tx, init_rx);
            })
            .expect("Failed to fork init");

            init_pid_tx
                .send(init_pid.as_raw() as u32)
                .expect("Failed to send init pid");

            Ok(())
        })
        .context("Failed to fork trampoline process")?;

        // Close child console socket (if any)
        drop(console_fd);

        // Keep runtime's relevant ends from each channel
        let init_tx = pipe_to_init.write_end();
        let init_rx = pipe_from_init.read_end();

        // Pipe that receives the init PID from the trampoline process
        let mut init_pid_rx: channel::AsyncReceiver<u32> = init_pid_channel.read_end().into();

        debug!("Waiting for init pid of container {}", container);
        let pid = init_pid_rx
            .recv()
            .await
            .expect("Failed to receive init pid");
        debug!("Created container {} with pid {}", container, pid);

        // Reap the trampoline process which is (or will be) a zombie otherwise
        debug!("Waiting for trampoline process {} to exit", trampoline_pid);
        wait::waitpid(Some(trampoline_pid), None).expect("Failed to wait for trampoline process");

        Ok(Process {
            init_tx: init_tx.into(),
            init_rx: Some(init_rx.into()),
            console_stop: Some(stop),
            container: container.to_owned(),
            exit_status: None,
            pid,
            tx: self.tx.clone(),
            path: cmd,
            args: argv,
            env,
        })
    }
}

/// Wait for the spawned process to exit and return its exit status.
async fn wait_exit_status(
    init_pid: u32,
    mut init_rx: channel::AsyncReceiver<InitMessage>,
) -> ExitStatus {
    // Note that at this point, the next message from the init process must be the exit status from
    // the spawned process or an error due to an unexpected close of the channel (e.g. init died).
    let exec_exit = init_rx.recv().await;

    // Independently of the previous result, we have to reap the init process
    let init_exit = {
        let init_pid = unistd::Pid::from_raw(init_pid as i32);
        loop {
            match wait::waitpid(Some(init_pid), None) {
                Ok(wait::WaitStatus::Exited(_pid, code)) => {
                    break ExitStatus::Exit(code);
                }
                Ok(wait::WaitStatus::Signaled(_pid, signal, _dump)) => {
                    break ExitStatus::Signalled(signal as u8);
                }
                // Interrupted by a signal
                Err(nix::Error::EINTR) => continue,
                Ok(r) => panic!("Unexpected wait status of init: {:?}", r),
                Err(e) => panic!("Failed to waitpid on {}: {}", init_pid, e),
            }
        }
    };
    debug!("Init {} exit status: {}", init_pid, init_exit);

    let exit_status = match exec_exit {
        Ok(InitMessage::Exit { pid, exit_status }) => {
            debug!("Process {} exit status: {}", pid, exit_status);
            exit_status
        }
        Err(e) => {
            error!("Failed to receive exit status from init: {}", e);
            // The channel was closed before the exit status was sent. We take the exit status of
            // the init process instead.
            init_exit
        }
        Ok(msg) => panic!("Unexpected init message: {:?}", msg),
    };

    exit_status
}

#[async_trait]
impl super::state::Process for Process {
    fn pid(&self) -> Pid {
        self.pid
    }

    async fn spawn(&mut self) -> Result<(), Error> {
        // Tell init to start the container application
        let mut init_rx = self.init_rx.take().unwrap();

        self.init_tx
            .send(Exec {
                path: self.path.clone(),
                args: self.args.clone(),
                env: self.env.clone(),
            })
            .await
            .context("Failed to send exec to init")?;

        // If the child process refuses to start - kill it after 5 seconds
        match time::timeout(std::time::Duration::from_secs(5), init_rx.recv()).await {
            Ok(Ok(InitMessage::Forked { pid })) => {
                debug!("Spawned {} with pid {}", self.container, pid);
            }
            Ok(msg) => {
                panic!("Unexpected init message: {:?}", msg);
            }
            Err(_) => {
                error!(
                    "Timeout while waiting for {} to start. Sending SIGKILL to {}",
                    self.pid, self.pid
                );
                let process_group = unistd::Pid::from_raw(-(self.pid as i32));
                let sigkill = Some(sys::signal::SIGKILL);
                sys::signal::kill(process_group, sigkill).ok();
                return Ok(());
            }
        };

        // spawn a task that waits for the process exit status
        let tx = self.tx.clone();
        let init_pid = self.pid;
        let container = self.container.clone();
        let stop = self.console_stop.take().unwrap();
        self.exit_status = Some(Box::new(
            task::spawn(async move {
                let exit_status = wait_exit_status(init_pid, init_rx).await;

                stop.cancel();

                let event = ContainerEvent::Exit(exit_status.clone());
                tx.send(Event::Container(container, event))
                    .await
                    .expect("Failed to send exit status");

                exit_status
            })
            .unwrap_or_else(|e| panic!("Task error: {}", e)),
        ));

        Ok(())
    }

    async fn kill(&mut self, signal: Signal) -> Result<(), super::error::Error> {
        debug!("Sending {} to {}", signal.as_str(), self.pid);
        let process_group = unistd::Pid::from_raw(-(self.pid as i32));
        let sigterm = Some(signal);
        match sys::signal::kill(process_group, sigterm) {
            // The process is terminated already. Wait for the waittask to do it's job and resolve exit_status
            Err(nix::Error::ESRCH) => {
                debug!("Process {} already exited", self.pid);
                Ok(())
            }
            result => result.context(format!(
                "Failed to send signal {} {}",
                signal, process_group
            )),
        }
    }

    async fn wait(&mut self) -> Result<ExitStatus, Error> {
        let exit_status = self.exit_status.take().expect("Wait called twice");
        Ok(exit_status.await)
    }

    async fn destroy(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Construct the init and argv argument for the containers execve
fn init_argv(manifest: &Manifest, args: Option<&Vec<NonNullString>>) -> (CString, Vec<CString>) {
    // A container without an init shall not be started
    // Validation of init is done in `Manifest`
    let init = CString::new(
        manifest
            .init
            .as_ref()
            .expect("Attempt to use init from resource container")
            .to_str()
            .expect("Invalid init. This a bug in the manifest validation"),
    )
    .expect("Invalid init");

    // If optional arguments are defined, discard the values from the manifest.
    // if there are no optional args - take the values from the manifest if present
    // or nothing.
    let args = match (manifest.args.as_ref(), args) {
        (None, None) => &[],
        (None, Some(a)) => a.as_slice(),
        (Some(m), None) => m.as_slice(),
        (Some(_), Some(a)) => a.as_slice(),
    };

    let mut argv = Vec::with_capacity(1 + args.len());
    argv.push(init.clone());
    argv.extend({
        args.iter().map(|arg| {
            CString::new(arg.as_bytes())
                .expect("Invalid arg. This is a bug in the manifest or parameter validation")
        })
    });

    // argv
    (init, argv)
}

/// Construct the env argument for the containers execve. Optional args and env overwrite values from the
/// manifest.
fn env(manifest: &Manifest, env: Option<&HashMap<NonNullString, NonNullString>>) -> Vec<CString> {
    let mut result = Vec::with_capacity(2);
    result.push(
        CString::new(format!("{}={}", ENV_NAME, manifest.name))
            .expect("Invalid container name. This is a bug in the manifest validation"),
    );
    result.push(CString::new(format!("{}={}", ENV_VERSION, manifest.version)).unwrap());

    if let Some(ref e) = manifest.env {
        result.extend({
            e.iter()
                .filter(|(k, _)| {
                    // Skip the values declared in fn arguments
                    env.map(|env| !env.contains_key(k)).unwrap_or(true)
                })
                .map(|(k, v)| {
                    CString::new(format!("{}={}", k, v))
                        .expect("Invalid env. This is a bug in the manifest validation")
                })
        })
    }

    // Add additional env variables passed
    if let Some(env) = env {
        result.extend(
            env.iter().map(|(k, v)| {
                CString::new(format!("{}={}", k, v)).expect("Invalid additional env")
            }),
        );
    }

    result
}

/// Open a socket that is passed via env variable to the child. The peer of the
/// socket is a console connection handling task
async fn console_fd(
    event_tx: EventTx,
    manifest: &Manifest,
    env: &mut Vec<CString>,
    fds: &mut HashMap<i32, io::Fd>,
    stop: CancellationToken,
    notification_tx: &NotificationTx,
) -> Option<StdUnixStream> {
    if manifest.console {
        let (runtime_socket, client_socket) = socket::socketpair(
            socket::AddressFamily::Unix,
            socket::SockType::Stream,
            None,
            socket::SockFlag::empty(),
        )
        .expect("Failed to create socketpair");

        // Add the fd number to the environment of the application
        env.push(CString::new(format!("NORTHSTAR_CONSOLE={}", client_socket)).unwrap());

        // Make sure that the server socket is closed in the child before exeve
        fds.insert(runtime_socket, io::Fd::Close);
        // Make sure the client socket is not included in the list to close fds
        fds.remove(&client_socket.as_raw_fd());

        // Convert std raw fd
        let std = unsafe { StdUnixStream::from_raw_fd(runtime_socket) };
        std.set_nonblocking(true)
            .expect("Failed to set socket into nonblocking mode");
        let io = UnixStream::from_std(std).expect("Failed to convert Unix socket");

        let peer = Peer::from(format!("{}:{}", manifest.name, manifest.version).as_str());

        // Start console
        task::spawn(console::Console::connection(
            io,
            peer,
            stop,
            event_tx,
            notification_tx.subscribe(),
            None,
        ));

        Some(unsafe { StdUnixStream::from_raw_fd(client_socket) })
    } else {
        None
    }
}

/// Generate a list of supplementary gids if the groups info can be retrieved. This
/// must happen before the init `clone` because the group information cannot be gathered
/// without `/etc` etc...
fn groups(manifest: &Manifest) -> Vec<u32> {
    if let Some(groups) = manifest.suppl_groups.as_ref() {
        let mut result = Vec::with_capacity(groups.len());
        for group in groups {
            let cgroup = CString::new(group.as_str()).unwrap(); // Check during manifest parsing
            let group_info =
                unsafe { nix::libc::getgrnam(cgroup.as_ptr() as *const nix::libc::c_char) };
            if group_info == (null::<c_void>() as *mut nix::libc::group) {
                warn!("Skipping invalid supplementary group {}", group);
            } else {
                let gid = unsafe { (*group_info).gr_gid };
                // TODO: Are there gids cannot use?
                result.push(gid)
            }
        }
        result
    } else {
        Vec::with_capacity(0)
    }
}

/// Generate seccomp filter applied in init
fn seccomp_filter(manifest: &Manifest) -> Option<seccomp::AllowList> {
    if let Some(seccomp) = manifest.seccomp.as_ref() {
        return Some(seccomp::seccomp_filter(
            seccomp.profile.as_ref(),
            seccomp.allow.as_ref(),
            manifest.capabilities.as_ref(),
        ));
    }
    None
}

// Set the child subreaper flag of the calling thread
fn set_child_subreaper(value: bool) -> Result<(), Error> {
    #[cfg(target_os = "android")]
    const PR_SET_CHILD_SUBREAPER: nix::libc::c_int = 36;
    #[cfg(not(target_os = "android"))]
    use nix::libc::PR_SET_CHILD_SUBREAPER;

    let value = if value { 1u64 } else { 0u64 };
    let result = unsafe { nix::libc::prctl(PR_SET_CHILD_SUBREAPER, value, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .context("Set child subreaper flag")
}
