use super::{
    config::Config,
    error::Error,
    ipc::{
        channel,
        condition::{self, ConditionNotify, ConditionWait},
    },
    ContainerEvent, Event, EventTx, ExitStatus, NotificationTx, Pid, ENV_NAME, ENV_VERSION,
};
use crate::{
    common::{container::Container, non_null_string::NonNullString},
    npk::manifest::Manifest,
    runtime::{
        console::{self, Peer},
        error::Context,
    },
    seccomp,
};
use async_trait::async_trait;
use futures::{future::ready, Future, FutureExt};
use log::{debug, error, info, warn};
use nix::{
    errno::Errno,
    sys::{self, signal::Signal, socket},
    unistd,
};
use std::{
    collections::HashMap,
    ffi::{c_void, CString},
    fmt,
    mem::forget,
    os::unix::{
        net::UnixStream as StdUnixStream,
        prelude::{AsRawFd, FromRawFd, RawFd},
    },
    path::Path,
    ptr::null,
};
use sys::wait;
use tokio::{net::UnixStream, task, time};
use tokio_util::sync::CancellationToken;

mod fs;
mod init;
mod io;
mod trampoline;

#[derive(Debug)]
pub(super) struct Launcher {
    tx: EventTx,
    notification_tx: NotificationTx,
    config: Config,
}

pub(super) struct Process {
    pid: Pid,
    checkpoint: Option<Checkpoint>,
    exit_status: Option<Box<dyn Future<Output = ExitStatus> + Send + Sync + Unpin>>,
}

impl fmt::Debug for Process {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Process")
            .field("pid", &self.pid)
            .field("checkpoint", &self.checkpoint)
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
        let (init, argv) = init_argv(manifest, args);
        let mut env = self::env(manifest, env);

        // Setup io and collect fd setup set
        let (io, mut fds) = io::from_manifest(manifest).await?;

        // Pipe for sending the init pid from the intermediate process to the runtime
        // and the exit status from init to the runtime
        //
        // Ensure the fds of the channel are *not* in the fds set. The list of fds that are
        // closed by init is gathered above. Between the assembly of the list and the new pipes
        // for the child pid and the condition variables a io task that forwards logs from containers
        // can end. Those io tasks use pipes as well. If such a task ends it closes its fds. Those numbers
        // can be in the list of to be closed fds but are reused when the pipe are created.
        let channel = channel::Channel::new();
        fds.remove(&channel.as_raw_fd().0);
        fds.remove(&channel.as_raw_fd().1);

        // Ensure that the checkpoint fds are not in the fds set and untouched
        let (checkpoint_runtime, checkpoint_init) = checkpoints();
        fds.remove(&checkpoint_runtime.as_raw_fd().0);
        fds.remove(&checkpoint_runtime.as_raw_fd().1);

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

        debug!("{} init is {:?}", container, init);
        debug!("{} argv is {:?}", container, argv);
        debug!("{} env is {:?}", container, env);

        let init = init::Init {
            root,
            init,
            argv,
            env,
            uid,
            gid,
            mounts,
            fds,
            groups,
            capabilities,
            rlimits,
            seccomp,
        };

        // Fork trampoline process
        match unsafe { unistd::fork() } {
            Ok(result) => match result {
                unistd::ForkResult::Parent { child } => {
                    let trampoline_pid = child;
                    // Close writing ends of log pipes (if any)
                    drop(io);
                    // Close child console socket (if any)
                    drop(console_fd);
                    // Close child checkpoint pipes
                    drop(checkpoint_init);

                    // Receive the pid of the init process from the trampoline process
                    debug!("Waiting for the pid of init of {}", container);
                    let mut channel = channel.into_async_read();
                    let pid = channel.recv::<i32>().await.expect("Failed to read pid") as Pid;
                    debug!("Created {} with pid {}", container, pid);

                    // We're done reading the pid. The next information transferred via the
                    // channel is the exit status of the container process.

                    // Reap the trampoline process which is (or will be) a zombie otherwise
                    debug!("Waiting for trampoline process {} to exit", trampoline_pid);
                    wait::waitpid(Some(trampoline_pid), None)
                        .expect("Failed to wait for trampoline process");

                    // Start a task that waits for the exit of the init process
                    let exit_status_fut = self.container_exit_status(container, channel, pid, stop);

                    Ok(Process {
                        pid,
                        checkpoint: Some(checkpoint_runtime),
                        exit_status: Some(Box::new(exit_status_fut)),
                    })
                }
                unistd::ForkResult::Child => {
                    // Forget writing ends of io which are stdout, stderr. The `forget`
                    // ensures that the file descriptors are not closed
                    forget(io);

                    // Close checkpoint ends of the runtime
                    drop(checkpoint_runtime);

                    trampoline::trampoline(init, channel, checkpoint_init)
                }
            },
            Err(e) => panic!("Fork error: {}", e),
        }
    }

    /// Spawn a task that waits for the containers exit status. If the receive operation
    /// fails take the exit status of the init process `pid`.
    fn container_exit_status(
        &self,
        container: &Container,
        mut channel: channel::AsyncChannelRead,
        pid: Pid,
        stop: CancellationToken,
    ) -> impl Future<Output = ExitStatus> {
        let container = container.clone();
        let tx = self.tx.clone();

        // This task lives as long as the child process and doesn't need to be
        // cancelled explicitly.
        task::spawn(async move {
            // Wait for an event on the channel
            let status = match channel.recv::<ExitStatus>().await {
                // Init sent something
                Ok(exit_status) => {
                    debug!(
                        "Received exit status of {} ({}) via channel: {}",
                        container, pid, exit_status
                    );

                    // Wait for init to exit. This is needed to ensure the init process
                    // exited before the runtime starts to cleanup e.g remove cgroups
                    if let Err(e) = wait::waitpid(Some(unistd::Pid::from_raw(pid as i32)), None) {
                        panic!("Failed to wait for init process {}: {}", pid, e);
                    }

                    exit_status
                }
                // The channel is closed before init sent something
                Err(e) => {
                    // This is not an error. If for example the child process exited because
                    // of a SIGKILL the pipe is just closed and the init process cannot send
                    // anything there. In such a situation take the exit status of the init
                    // process as the exit status of the container process.
                    debug!(
                        "Failed to receive exit status of {} ({}) via channel: {}",
                        container, pid, e
                    );

                    let pid = unistd::Pid::from_raw(pid as i32);
                    let exit_status = loop {
                        match wait::waitpid(Some(pid), None) {
                            Ok(wait::WaitStatus::Exited(pid, code)) => {
                                debug!("Process {} exit code is {}", pid, code);
                                break ExitStatus::Exit(code);
                            }
                            Ok(wait::WaitStatus::Signaled(pid, signal, _dump)) => {
                                debug!("Process {} exit status is signal {}", pid, signal);
                                break ExitStatus::Signalled(signal as u8);
                            }
                            Ok(r) => unreachable!("Unexpected wait status of init: {:?}", r),
                            Err(nix::Error::EINTR) => continue,
                            Err(e) => panic!("Failed to waitpid on {}: {}", pid, e),
                        }
                    };
                    debug!("Exit status of {} ({}): {}", container, pid, exit_status);
                    exit_status
                }
            };

            // Stop console connection if any
            stop.cancel();

            // Send container exit event to the runtime main loop
            let event = ContainerEvent::Exit(status.clone());
            tx.send(Event::Container(container, event))
                .await
                .expect("Failed to send container event");

            status
        })
        .then(|r| match r {
            Ok(r) => ready(r),
            Err(_) => panic!("Task error"),
        })
    }
}

#[async_trait]
impl super::state::Process for Process {
    fn pid(&self) -> Pid {
        self.pid
    }

    async fn spawn(&mut self) -> Result<(), Error> {
        let checkpoint = self
            .checkpoint
            .take()
            .expect("Attempt to start container twice. This is a bug.");
        info!("Starting {}", self.pid());
        let wait = checkpoint.notify();

        // If the child process refuses to start - kill it after 5 seconds
        match time::timeout(time::Duration::from_secs(5), wait.async_wait()).await {
            Ok(_) => (),
            Err(_) => {
                error!(
                    "Timeout while waiting for {} to start. Sending SIGKILL to {}",
                    self.pid, self.pid
                );
                let process_group = unistd::Pid::from_raw(-(self.pid as i32));
                let sigkill = Some(sys::signal::SIGKILL);
                sys::signal::kill(process_group, sigkill).ok();
            }
        }

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

pub(super) struct Checkpoint(ConditionWait, ConditionNotify);

fn checkpoints() -> (Checkpoint, Checkpoint) {
    let a = condition::Condition::new().expect("Failed to create condition");
    a.set_cloexec();
    let b = condition::Condition::new().expect("Failed to create condition");
    b.set_cloexec();

    let (aw, an) = a.split();
    let (bw, bn) = b.split();

    (Checkpoint(aw, bn), Checkpoint(bw, an))
}

impl Checkpoint {
    fn notify(self) -> ConditionWait {
        self.1.notify();
        self.0
    }

    fn wait(self) -> ConditionNotify {
        self.0.wait();
        self.1
    }

    /// Raw file descriptor number of the rx and tx pipe
    fn as_raw_fd(&self) -> (RawFd, RawFd) {
        (self.0.as_raw_fd(), self.1.as_raw_fd())
    }
}

impl std::fmt::Debug for Checkpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Checkpoint")
            .field("wait", &self.0.as_raw_fd())
            .field("notifiy", &self.1.as_raw_fd())
            .finish()
    }
}
