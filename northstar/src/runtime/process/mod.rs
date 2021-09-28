use super::{
    config::Config,
    error::Error,
    pipe::{self, ConditionNotify, ConditionWait},
    ContainerEvent, Event, EventTx, ExitStatus, NotificationTx, Pid, ENV_NAME, ENV_VERSION,
};
use crate::{
    common::{container::Container, non_null_string::NonNullString},
    npk::manifest::{Manifest, RLimitResource, RLimitValue},
    runtime::console::{self, Peer},
    seccomp,
};
use async_trait::async_trait;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use caps::CapsHashSet;
use futures::{Future, FutureExt};
use log::{debug, error, info, warn};
use nix::{
    errno::Errno,
    sched,
    sys::{self, signal::Signal, socket, wait::WaitPidFlag},
    unistd,
};
use std::{
    collections::HashMap,
    convert::TryFrom,
    ffi::{c_void, CString},
    fmt,
    mem::forget,
    os::unix::{
        net::UnixStream as StdUnixStream,
        prelude::{AsRawFd, FromRawFd},
    },
    path::PathBuf,
    process::exit,
    ptr::null,
};
use sys::wait;
use tokio::{net::UnixStream, signal, task, time};
use tokio_util::sync::CancellationToken;

mod fs;
mod init;
mod io;

/// Offset for signal as exit code encoding
const SIGNAL_OFFSET: i32 = 128;

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
        root: PathBuf,
        container: Container,
        manifest: Manifest,
        args: Option<&Vec<NonNullString>>,
        env: Option<&HashMap<NonNullString, NonNullString>>,
    ) -> Result<impl super::state::Process, Error> {
        // Token to stop the console task if any. This token is cancelled when
        // the waitpid of this child process signals that the child is exited. See
        // `wait`.
        let stop = CancellationToken::new();
        let mounts = fs::prepare_mounts(&self.config, &root, manifest.clone()).await?;
        let (init, argv) = init_argv(&manifest, args);
        let mut env = self::env(&manifest, env);
        let (io, mut fds) = io::from_manifest(&manifest).await?;
        let console_fd = console_fd(
            self.tx.clone(),
            &manifest,
            &mut env,
            &mut fds,
            stop.clone(),
            &self.notification_tx,
        )
        .await;
        let fds = fds.drain().collect::<Vec<_>>();
        let (checkpoint_runtime, checkpoint_init) = checkpoints();
        let groups = groups(&manifest);
        let capabilities = capabilities(&manifest);
        let rlimits = rlimits(&manifest);
        let seccomp = seccomp_filter(&manifest);

        debug!("{} init is {:?}", manifest.name, init);
        debug!("{} argv is {:?}", manifest.name, argv);
        debug!("{} env is {:?}", manifest.name, env);

        let init = init::Init {
            manifest,
            root,
            init,
            argv,
            env,
            mounts,
            fds,
            groups,
            capabilities,
            rlimits,
            seccomp,
        };

        // Pipe for sending the init pid from the intermediate process to the runtime
        let pid_channel = Channel::new();

        // Clone init
        match unsafe { unistd::fork() } {
            Ok(result) => match result {
                unistd::ForkResult::Parent { child } => {
                    // Close writing ends of log pipes
                    drop(io);
                    // Close child console socket if any
                    drop(console_fd);
                    // Close child checkpoint pipes
                    drop(checkpoint_init);

                    debug!("Waiting for init pid of {}", container);
                    let pid = pid_channel.recv().expect("Failed to read pid") as Pid;

                    debug!("Created {} with pid {}", container, pid);

                    // Reap the trampoline process which is (or will be) a zombie
                    debug!("Waiting for trampoline process {} to exit", child);
                    wait::waitpid(Some(child), None)
                        .expect("Failed to wait for trampoline process");

                    // Create a future that resolves upon exit of init
                    let exit_status = waitpid(container, pid, self.tx.clone(), stop);

                    Ok(Process {
                        pid,
                        checkpoint: Some(checkpoint_runtime),
                        exit_status: Some(Box::new(exit_status)),
                    })
                }
                unistd::ForkResult::Child => {
                    // Close io reading ends (if any)
                    forget(io);
                    // Close runtime checkpoints
                    drop(checkpoint_runtime);

                    // Create PID namespace. Init is the first process that is spawned
                    // into this pid namespace. The container application itself is spawned
                    // by init
                    sched::unshare(sched::CloneFlags::CLONE_NEWPID)
                        .expect("Failed to unshare NEWPID");

                    match unsafe { unistd::fork() }.expect("Failed to fork init") {
                        unistd::ForkResult::Child => {
                            // We're init and do not care how our pid is sent to the runtime
                            drop(pid_channel);

                            // Wait for the runtime to signal that init may start.
                            let condition_notify = checkpoint_init.wait();

                            // Dive into init and never return
                            init.run(condition_notify);
                        }
                        unistd::ForkResult::Parent { child } => {
                            // Send the pid of init to the runtime and exit
                            pid_channel
                                .send(child.as_raw() as u32)
                                .expect("Failed to send init pid");
                            exit(0);
                        }
                    }
                }
            },
            Err(e) => panic!("Fork error: {}", e),
        }
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
            Ok(_) => {}
            // The process is terminated already. Wait for the waittask to do it's job and resolve exit_status
            Err(nix::Error::Sys(errno)) if errno == Errno::ESRCH => {
                debug!("Process {} already exited", self.pid);
            }
            Err(e) => {
                return Err(Error::Os(
                    format!("Failed to send signal {} {}", signal, process_group),
                    e,
                ))
            }
        }
        Ok(())
    }

    async fn wait(&mut self) -> Result<ExitStatus, Error> {
        let exit_status = self.exit_status.take().expect("Wait called twice");
        Ok(exit_status.await)
    }

    async fn destroy(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Spawn a task that waits for the process to exit. Resolves to the exit status of `pid`.
fn waitpid(
    container: Container,
    pid: Pid,
    tx: EventTx,
    stop: CancellationToken,
) -> impl Future<Output = ExitStatus> {
    task::spawn(async move {
        let mut sigchld = signal::unix::signal(signal::unix::SignalKind::child())
            .expect("Failed to set up signal handle for SIGCHLD");

        // Check the status of the process after every SIGCHLD is received
        let exit_status = loop {
            sigchld.recv().await;
            if let Some(exit) = exit_status(pid) {
                stop.cancel();
                break exit;
            }
        };

        drop(
            tx.send(Event::Container(
                container,
                ContainerEvent::Exit(exit_status.clone()),
            ))
            .await,
        );
        exit_status
    })
    .map(|r| r.expect("Task join error"))
}

/// Get exit status of process with `pid` or None
fn exit_status(pid: Pid) -> Option<ExitStatus> {
    let pid = unistd::Pid::from_raw(pid as i32);
    match wait::waitpid(Some(pid), Some(WaitPidFlag::WNOHANG)) {
        // The process exited normally (as with exit() or returning from main) with the given exit code.
        // This case matches the C macro WIFEXITED(status); the second field is WEXITSTATUS(status).
        Ok(wait::WaitStatus::Exited(pid, code)) => {
            // There is no way to make the "init" exit with a signal status. Use a defined
            // offset to get the original signal. This is the sad way everyone does it...
            if SIGNAL_OFFSET <= code {
                let signal = Signal::try_from(code - SIGNAL_OFFSET).expect("Invalid signal offset");
                debug!("Process {} exit status is signal {}", pid, signal);
                Some(ExitStatus::Signaled(signal))
            } else {
                debug!("Process {} exit code is {}", pid, code);
                Some(ExitStatus::Exit(code))
            }
        }

        // The process was killed by the given signal.
        // The third field indicates whether the signal generated a core dump. This case matches the C macro WIFSIGNALED(status); the last two fields correspond to WTERMSIG(status) and WCOREDUMP(status).
        Ok(wait::WaitStatus::Signaled(pid, signal, _dump)) => {
            debug!("Process {} exit status is signal {}", pid, signal);
            Some(ExitStatus::Signaled(signal))
        }

        // The process is alive, but was stopped by the given signal.
        // This is only reported if WaitPidFlag::WUNTRACED was passed. This case matches the C macro WIFSTOPPED(status); the second field is WSTOPSIG(status).
        Ok(wait::WaitStatus::Stopped(_pid, _signal)) => None,

        // The traced process was stopped by a PTRACE_EVENT_* event.
        // See nix::sys::ptrace and ptrace(2) for more information. All currently-defined events use SIGTRAP as the signal; the third field is the PTRACE_EVENT_* value of the event.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Ok(wait::WaitStatus::PtraceEvent(_pid, _signal, _)) => None,

        // The traced process was stopped by execution of a system call, and PTRACE_O_TRACESYSGOOD is in effect.
        // See ptrace(2) for more information.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Ok(wait::WaitStatus::PtraceSyscall(_pid)) => None,

        // The process was previously stopped but has resumed execution after receiving a SIGCONT signal.
        // This is only reported if WaitPidFlag::WCONTINUED was passed. This case matches the C macro WIFCONTINUED(status).
        Ok(wait::WaitStatus::Continued(_pid)) => None,

        // There are currently no state changes to report in any awaited child process.
        // This is only returned if WaitPidFlag::WNOHANG was used (otherwise wait() or waitpid() would block until there was something to report).
        Ok(wait::WaitStatus::StillAlive) => None,
        // Retry the waitpid call if waitpid fails with EINTR
        Err(e) if e == nix::Error::Sys(Errno::EINTR) => None,
        Err(e) if e == nix::Error::Sys(Errno::ECHILD) => {
            panic!("Waitpid returned ECHILD. This is bug.");
        }
        Err(e) => panic!("Failed to waitpid on {}: {}", pid, e),
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
        CString::new(format!("{}={}", ENV_NAME, manifest.name.to_string()))
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

/// Capability settings applied in init
struct Capabilities {
    all: CapsHashSet,
    bounded: CapsHashSet,
    set: CapsHashSet,
}

/// Calculate capability sets
fn capabilities(manifest: &Manifest) -> Capabilities {
    let all = caps::all();
    let mut bounded =
        caps::read(None, caps::CapSet::Bounding).expect("Failed to read bounding caps");
    let set = manifest.capabilities.clone().unwrap_or_default();
    bounded.retain(|c| !set.contains(c));
    Capabilities { all, bounded, set }
}

type RLimits = HashMap<rlimit::Resource, RLimitValue>;

fn rlimits(manifest: &Manifest) -> RLimits {
    manifest
        .rlimits
        .as_ref()
        .map(|l| {
            l.iter()
                .map(|(k, v)| {
                    let resource = match k {
                        RLimitResource::AS => rlimit::Resource::AS,
                        RLimitResource::CORE => rlimit::Resource::CORE,
                        RLimitResource::CPU => rlimit::Resource::CPU,
                        RLimitResource::DATA => rlimit::Resource::DATA,
                        RLimitResource::FSIZE => rlimit::Resource::FSIZE,
                        RLimitResource::LOCKS => rlimit::Resource::LOCKS,
                        RLimitResource::MEMLOCK => rlimit::Resource::MEMLOCK,
                        RLimitResource::MSGQUEUE => rlimit::Resource::MSGQUEUE,
                        RLimitResource::NICE => rlimit::Resource::NICE,
                        RLimitResource::NOFILE => rlimit::Resource::NOFILE,
                        RLimitResource::NPROC => rlimit::Resource::NPROC,
                        RLimitResource::RSS => rlimit::Resource::RSS,
                        RLimitResource::RTPRIO => rlimit::Resource::RTPRIO,
                        #[cfg(not(target_os = "android"))]
                        RLimitResource::RTTIME => rlimit::Resource::RTTIME,
                        RLimitResource::SIGPENDING => rlimit::Resource::SIGPENDING,
                        RLimitResource::STACK => rlimit::Resource::STACK,
                    };
                    (resource, v.clone())
                })
                .collect()
        })
        .unwrap_or_default()
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
        .map_err(|e| Error::os("Set child subreaper flag", e))
}

#[derive(Clone)]
pub(super) struct Checkpoint(ConditionWait, ConditionNotify);

fn checkpoints() -> (Checkpoint, Checkpoint) {
    let a = pipe::Condition::new().expect("Failed to create condition");
    a.set_cloexec();
    let b = pipe::Condition::new().expect("Failed to create condition");
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
}

impl std::fmt::Debug for Checkpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Checkpoint")
            .field("wait", &self.0.as_raw_fd())
            .field("notifiy", &self.1.as_raw_fd())
            .finish()
    }
}

/// Wrap a pipe for sending the init pid from the trampoline to the runtime
struct Channel {
    tx: pipe::PipeWrite,
    rx: pipe::PipeRead,
}

impl Channel {
    fn new() -> Channel {
        let (rx, tx) = pipe::pipe().expect("Failed to create pipe");
        Channel { tx, rx }
    }

    fn send(mut self, v: u32) -> std::io::Result<()> {
        self.tx.write_u32::<BigEndian>(v)
    }

    fn recv(mut self) -> std::io::Result<u32> {
        self.rx.read_u32::<BigEndian>()
    }
}
