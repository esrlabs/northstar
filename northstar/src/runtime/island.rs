// Copyright (c) 2021 ESRLabs
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
    pipe::{pipe, pipe_duplex, AsyncPipeRead, Condition, PipeRead, PipeSendRecv, PipeWrite},
    Event, EventTx, ExitStatus, Launcher, MountedContainer as Container, Pid, Process,
};
use anyhow::Context;
use async_trait::async_trait;
use futures::{Future, TryFutureExt};
use log::{debug, error, info, trace, warn, Level};
use nix::{
    errno::Errno,
    libc::{self, c_int, c_ulong, siginfo_t},
    mount::{self, MsFlags},
    sched,
    sys::{
        self,
        signal::{
            kill, sigaction, signal, SaFlags, SigAction, SigHandler, SigSet, Signal, SIGCHLD,
            SIGKILL,
        },
    },
    unistd::{self, ForkResult, Uid},
};
use npk::manifest::{Dev, Mount, MountFlag};
use sched::CloneFlags;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    env,
    ffi::{c_void, CString},
    fmt,
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
    process::exit,
};
use sys::wait::{waitpid, WaitStatus};
use tokio::{io, io::AsyncBufReadExt, select, task, time};
use tokio_util::sync::CancellationToken;

const ENV_NAME: &str = "NAME";
const ENV_VERSION: &str = "VERSION";
const SIGNAL_OFFSET: i32 = 128;

type Intercom = (PipeRead, PipeWrite);

#[allow(unused)]
macro_rules! ctrace { ($($arg:tt)+) => (log::trace!("{}: {}", std::process::id(), format!($($arg)+))) }
#[allow(unused)]
macro_rules! cdebug { ($($arg:tt)+) => (log::debug!("{}: {}", std::process::id(), format!($($arg)+))) }
#[allow(unused)]
macro_rules! cinfo { ($($arg:tt)+) => ( log::warn!("{}: {}", std::process::id(), format!($($arg)+))) }
#[allow(unused)]
macro_rules! cwarn { ($($arg:tt)+) => ( log::warn!("{}: {}", std::process::id(), format!($($arg)+))) }
#[allow(unused)]
macro_rules! cerror { ($($arg:tt)+) => ( log::error!("{}: {}", std::process::id(), format!($($arg)+))) }

#[derive(Serialize, Deserialize)]
enum LaunchProtocol {
    Error(String),
    InitReady,
    Go,
}

#[derive(Debug)]
pub(super) struct Island {
    tx: EventTx,
    config: Config,
}

pub(super) enum IslandProcess {
    Created {
        pid: Pid,
        intercom: Intercom,
        exit_status: Box<dyn Future<Output = Result<ExitStatus, Error>> + Unpin + Send + Sync>,
        io: (Option<Log>, Option<Log>),
    },
    Started {
        pid: Pid,
        exit_status: Box<dyn Future<Output = Result<ExitStatus, Error>> + Unpin + Send + Sync>,
        io: (Option<Log>, Option<Log>),
    },
    Stopped {
        pid: Pid,
    },
}

impl fmt::Debug for IslandProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IslandProcess::Created { pid, .. } => f
                .debug_struct("IslandProcess::Created")
                .field("pid", &pid)
                .finish(),
            IslandProcess::Started { pid, .. } => f
                .debug_struct("IslandProcess::Started")
                .field("pid", &pid)
                .finish(),
            IslandProcess::Stopped { pid } => f
                .debug_struct("IslandProcess::Stoped")
                .field("pid", &pid)
                .finish(),
        }
    }
}

trait PathExt {
    fn join_strip<T: AsRef<Path>>(&self, w: T) -> PathBuf;
}

impl PathExt for Path {
    fn join_strip<T: AsRef<Path>>(&self, w: T) -> PathBuf {
        if w.as_ref().starts_with("/") {
            self.join(w.as_ref().strip_prefix("/").unwrap())
        } else {
            self.join(w)
        }
    }
}

#[async_trait]
impl Launcher for Island {
    type Process = IslandProcess;

    async fn start(tx: EventTx, config: Config) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(Island { tx, config })
    }

    async fn shutdown(self) -> Result<(), Error>
    where
        Self: Sized,
    {
        Ok(())
    }

    async fn create(&self, container: &Container<Self::Process>) -> Result<Self::Process, Error> {
        // Intercom
        let (intercom_runtime, intercom_init) = pipe_duplex::<PipeRead, PipeWrite>()
            .map_err(|e| Error::io("Failed to create duplex", e))?;

        // Setup childs io
        let mut child_fd_map = HashMap::new();
        let (stdout, stderr) = if let Some(io) = container.manifest.io.as_ref() {
            let stdout = match io.stdout {
                Some(npk::manifest::Output::Pipe) => {
                    child_fd_map.insert(nix::libc::STDOUT_FILENO, nix::libc::STDOUT_FILENO);
                    None
                }
                Some(npk::manifest::Output::Log { level, ref tag }) => {
                    let log = Log::new(level, tag).await?;
                    trace!("Stdout pipe fd is {}", log.writer.as_raw_fd());
                    child_fd_map.insert(nix::libc::STDOUT_FILENO, log.writer.as_raw_fd());
                    Some(log)
                }
                None => None,
            };
            let stderr = match io.stderr {
                Some(npk::manifest::Output::Pipe) => {
                    child_fd_map.insert(nix::libc::STDERR_FILENO, nix::libc::STDERR_FILENO);
                    None
                }
                Some(npk::manifest::Output::Log { level, ref tag }) => {
                    let log = Log::new(level, tag).await?;
                    trace!("Stderr pipe fd is {}", log.writer.as_raw_fd());
                    child_fd_map.insert(nix::libc::STDERR_FILENO, log.writer.as_raw_fd());
                    Some(log)
                }
                None => None,
            };
            (stdout, stderr)
        } else {
            (None, None)
        };

        // Clone init
        let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS;
        match clone(flags, Some(SIGCHLD as i32)) {
            Ok(result) => match result {
                unistd::ForkResult::Parent { child } => {
                    let pid = child.as_raw() as Pid;
                    let exit_status = Box::new(wait(container, pid, self.tx.clone()).await);

                    Ok(IslandProcess::Created {
                        pid,
                        exit_status,
                        intercom: intercom_runtime,
                        io: (stdout, stderr),
                    })
                }
                unistd::ForkResult::Child => {
                    init(&self.config, container, child_fd_map, intercom_init)
                }
            },
            Err(e) => panic!("Fork error: {}", e),
        }
    }
}

#[async_trait]
impl Process for IslandProcess {
    fn pid(&self) -> Pid {
        match self {
            IslandProcess::Created { pid, .. } => *pid,
            IslandProcess::Started { pid, .. } => *pid,
            IslandProcess::Stopped { pid } => *pid,
        }
    }

    async fn start(mut self) -> Result<Self, Error> {
        info!("Starting {}", self.pid());
        match self {
            IslandProcess::Created {
                pid,
                exit_status,
                mut intercom,
                io: _io,
            } => {
                intercom.send(LaunchProtocol::Go).ok();
                intercom.recv::<LaunchProtocol>().ok();
                Ok(IslandProcess::Started {
                    pid,
                    exit_status,
                    io: _io,
                })
            }
            _ => unreachable!(),
        }
    }

    /// Send a SIGTERM to the application. If the application does not terminate with a timeout
    /// it is SIGKILLed.
    async fn stop(
        mut self,
        timeout: time::Duration,
    ) -> Result<(Self, ExitStatus), super::error::Error> {
        let (pid, mut exit_status) = match self {
            IslandProcess::Created {
                pid, exit_status, ..
            } => (pid, exit_status),
            IslandProcess::Started {
                pid,
                exit_status,
                io: _io,
            } => (pid, exit_status),
            IslandProcess::Stopped { .. } => unreachable!(),
        };
        debug!("Trying to send SIGTERM to {}", pid);
        let pid = unistd::Pid::from_raw(pid as i32);
        let sigterm = Some(sys::signal::SIGTERM);
        let exit_status = match sys::signal::kill(pid, sigterm) {
            Ok(_) => {
                match time::timeout(timeout, &mut exit_status).await {
                    Err(_) => {
                        warn!(
                            "Process {} did not exit within {:?}. Sending SIGKILL...",
                            pid, timeout
                        );
                        // Send SIGKILL if the process did not terminate before timeout
                        let sigkill = Some(sys::signal::SIGKILL);
                        sys::signal::kill(pid, sigkill)
                            .map_err(|e| Error::Os("Failed to kill process".to_string(), e))?;

                        (&mut exit_status).await
                    }
                    Ok(exit_status) => exit_status,
                }
            }
            // The proces is terminated already. Wait for the waittask to do it's job and resolve exit_status
            Err(nix::Error::Sys(errno)) if errno == nix::errno::Errno::ESRCH => {
                debug!("Process {} already exited. Waiting for status", pid);
                let exit_status = exit_status.await?;
                Ok(exit_status)
            }
            Err(e) => Err(Error::Os(format!("Failed to SIGTERM {}", pid), e)),
        }?;

        let pid = pid.as_raw() as u32;
        Ok((IslandProcess::Stopped { pid }, exit_status))
    }

    async fn destroy(mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Init
fn init(
    config: &Config,
    container: &Container<IslandProcess>,
    mut fds: HashMap<i32, i32>,
    mut intercom: Intercom,
) -> ! {
    pr_set_name("init").expect("Failed to set init process name");

    // Add intercom to list of fds to preserve
    fds.insert(intercom.0.as_raw_fd(), intercom.0.as_raw_fd());
    fds.insert(intercom.1.as_raw_fd(), intercom.1.as_raw_fd());

    match init_prepare(&config, container, fds) {
        Ok(_) => {
            let id = format!("init-{}", container.manifest.name);

            // Synchronize parent and child startup since we have to rely on a global mut
            // because unix signal handler suck.
            let cond = Condition::new().expect("Failed to create pipe");

            match clone(CloneFlags::empty(), Some(SIGCHLD as i32)) {
                Ok(result) => match result {
                    unistd::ForkResult::Parent { child } => {
                        // Update global CHILD_PID
                        unsafe {
                            CHILD_PID = child.as_raw();
                        }
                        // Signal the child it can go
                        cond.notify();

                        //println!("{}: Waiting for go", id);
                        intercom.recv::<LaunchProtocol>().expect("intercom error");
                        intercom
                            .send(LaunchProtocol::InitReady)
                            .expect("intercom error");

                        drop(intercom);

                        // TODO: Anything we can do here to free stuff before waiting forever?

                        // If the child dies before we waitpid here it becomes a zombie and is catched

                        // Wait for the child to exit
                        //println!("{}: waiting for {} to exit", id, child);
                        let result = waitpid(Some(child), None).expect("waitpid");
                        //println!("{}: waitpid result of {}: {:?}", id, child, result);
                        match result {
                            WaitStatus::Exited(_pid, status) => exit(status),
                            WaitStatus::Signaled(_pid, status, _) => {
                                // Encode the signal number in the process exit status. It's not possible to raise a
                                // a signal in this "init" process that is received by our parent
                                let code = SIGNAL_OFFSET + status as i32;
                                //println!("{}: exiting with {} (signaled {})", id, code, status);
                                exit(code);
                            }
                            // TODO: Other waitpid results
                            _ => panic!("abnormal exit of child process"),
                        };
                    }
                    unistd::ForkResult::Child => {
                        cond.wait();
                        drop(intercom);
                        reset_signal_handlers();
                        set_pdeath_signal(SIGKILL).expect("Failed to set parent death signal");

                        let (init, argv, env) = init_args(&container.manifest);
                        println!("{} init: {:?}", id, init);
                        println!("{} argv: {:#?}", id, argv);
                        println!("{} env: {:#?}", id, env);

                        panic!("{}: {:?}", id, unistd::execve(&init, &argv, &env))
                    }
                },
                Err(e) => panic!("Fork error: {}", e),
            }
        }
        Err(e) => {
            warn!("Child init error: {:?}", e);
            intercom
                .send(LaunchProtocol::Error(e.to_string()))
                .expect("intercom error");
            panic!("Init error: {}", e);
        }
    };
}

fn init_prepare(
    config: &Config,
    container: &Container<IslandProcess>,
    fds: HashMap<i32, i32>,
) -> anyhow::Result<()> {
    let manifest = &container.manifest;
    let root = container.root.canonicalize()?;

    // Install signal handlers that forward every signal to our child
    init_signal_handlers();

    // Mount
    init_rootfs(&config, &container).context("Failed to mount")?;

    // Chroot
    cdebug!("Using chroot {}", root.display());
    unistd::chroot(&root).context("Failed to chroot")?;

    // Pwd
    cdebug!("Setting pwd to /");
    env::set_current_dir("/").context("Failed to set cwd to /")?;

    // UID / GID
    setid(manifest.uid, manifest.gid).context("Failed to setuid/gid")?;

    cdebug!("Setting no new privs");
    set_no_new_privs(true)?;

    // Set the parent process death signal of the calling process to arg2
    // (either a signal value in the range 1..maxsig, or 0 to clear).
    set_pdeath_signal(SIGKILL)?;

    init_close_fds(fds)?;

    // Capabilities
    drop_cap(manifest.capabilities.as_ref()).context("Failed to drop privs")?;

    // We cannot use log after here because the fd to logd is closed on Android

    Ok(())
}

// TODO: The container could be malformed and the mountpoint might be
// missing. This is not a fault of the RT so don't expect it.
// TODO: mount flags: nosuid etc....
// TODO: /dev mounts from manifest: full or minimal
fn init_rootfs(config: &Config, container: &Container<IslandProcess>) -> anyhow::Result<()> {
    let none = Option::<&str>::None;
    let root = container
        .root
        .canonicalize()
        .map_err(|e| Error::io("Failed to canonicalize root", e))?;
    let uid = container.manifest.uid;
    let gid = container.manifest.gid;

    // /proc
    cdebug!("Mounting /proc");
    let source = "/proc";
    let target = root.join("proc");
    mount::mount(none, &target, Some("proc"), MsFlags::empty(), none)
        .context("Failed to mount /proc")?;
    // Remount /proc ro
    cdebug!("Remount /proc read only");
    let flags = MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
    mount::mount(Some(source), &target, none, flags, none).context("Failed to remount /proc")?;

    fn mount_dev(root: &Path, _type: &Dev) -> anyhow::Result<()> {
        // TODO: Dev mount type
        cdebug!("Mounting /dev");
        let source = "/dev/";
        let target = root.join("dev");
        mount::mount(
            Some(source),
            &target,
            Option::<&str>::None,
            MsFlags::MS_BIND,
            Option::<&str>::None,
        )
        .context("Failed to mount /dev")
    }

    // TODO
    if !container
        .manifest
        .mounts
        .iter()
        .any(|(_, mount)| matches!(mount, Mount::Dev { .. }))
    {
        mount_dev(&root, &Dev::Full)?;
    }

    container
        .manifest
        .mounts
        .iter()
        .try_for_each(|(target, mount)| {
            match &mount {
                Mount::Bind { host, flags } => {
                    if !&host.exists() {
                        cwarn!(
                            "Cannot bind mount nonexitent source {} to {}",
                            host.display(),
                            target.display()
                        );
                        return Ok(());
                    }
                    let rw = flags.contains(&MountFlag::Rw);
                    cdebug!(
                        "Mounting {} on {}{}",
                        host.display(),
                        target.display(),
                        if rw { " (rw)" } else { "" }
                    );
                    let target = root.join_strip(target);
                    mount::mount(Some(host), &target, none, MsFlags::MS_BIND, none)
                        .with_context(|| format!("Failed to bind mount {}", target.display()))?;

                    if !rw {
                        let flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
                        mount::mount(Some(host), &target, none, flags, none)
                            .with_context(|| format!("Failed to remount {}", target.display()))?;
                    }
                }
                Mount::Persist => {
                    let dir = config.data_dir.join(&container.manifest.name);
                    if !dir.exists() {
                        cdebug!("Creating {}", dir.display());
                        std::fs::create_dir_all(&dir).map_err(|e| {
                            Error::Io(format!("Failed to create {}", dir.display()), e)
                        })?;
                    }

                    cdebug!("Chowning {} to {}:{}", dir.display(), uid, gid);
                    unistd::chown(
                        dir.as_os_str(),
                        Some(unistd::Uid::from_raw(uid)),
                        Some(unistd::Gid::from_raw(gid)),
                    )
                    .map_err(|e| {
                        Error::os(
                            format!("Failed to chown {} to {}:{}", dir.display(), uid, gid),
                            e,
                        )
                    })?;

                    cdebug!("Mounting {} on {}", dir.display(), target.display(),);

                    let target = root.join_strip(target);
                    mount::mount(Some(&dir), &target, none, MsFlags::MS_BIND, none)
                        .with_context(|| format!("Failed to bind mount {}", target.display()))?;
                }
                Mount::Resource { name, version, dir } => {
                    let src = {
                        // Join the source of the resource container with the mount dir
                        let resource_root = config.run_dir.join(format!("{}:{}", name, version));
                        let dir = dir
                            .strip_prefix("/")
                            .map(|d| resource_root.join(d))
                            .unwrap_or(resource_root);

                        if !dir.exists() {
                            return Err(anyhow::anyhow!("Missing resource {}", dir.display()));
                        }

                        dir
                    };

                    cdebug!("Mounting {} on {}", src.display(), target.display());

                    let target = root.join_strip(target);
                    mount::mount(Some(&src), &target, none, MsFlags::MS_BIND, none)
                        .with_context(|| format!("Failed to mount {}", target.display()))?;

                    // Remount ro
                    let flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
                    mount::mount(Some(&src), &target, none, flags, none)
                        .with_context(|| format!("Failed to remount {}", target.display()))?;
                }
                Mount::Tmpfs { size } => {
                    cdebug!(
                        "Mounting tmpfs with size {} on {}",
                        bytesize::ByteSize::b(*size),
                        target.display()
                    );
                    let target = root.join_strip(target);
                    let data = format!("size={},mode=1777", size);
                    let flags = MsFlags::empty();
                    mount::mount(none, &target, Some("tmpfs"), flags, Some(data.as_str()))
                        .with_context(|| format!("Failed to bind mount {}", target.display()))?;
                }
                Mount::Dev { r#type } => mount_dev(&root, r#type)?,
            }
            Ok(())
        })?;

    Ok(())
}

// TODO: Do not close the namespace fds?
fn init_close_fds(map: HashMap<i32, i32>) -> anyhow::Result<()> {
    let keep: HashSet<i32> = map.keys().cloned().collect();
    for (k, v) in map.iter().filter(|(k, v)| k != v) {
        // If the fd is mappped to a different fd create a copy
        cdebug!("Using fd {} mapped as fd {}", v, k);
        unistd::dup2(*v, *k).context("Failed to dup2")?;
    }

    // Close open fds which are not mapped
    let fd = Path::new("/proc")
        .join(unistd::getpid().to_string())
        .join("fd");

    let fds = std::fs::read_dir(&fd)
        .expect("Failed to read list of fds")
        .map(|e| e.unwrap().path())
        .map(|e| e.file_name().unwrap().to_str().unwrap().parse().unwrap())
        .filter(|fd| !keep.contains(fd))
        .collect::<Vec<_>>();

    cdebug!("Closing file descriptors");
    for fd in fds.iter() {
        unistd::close(*fd).ok();
    }

    Ok(())
}

fn init_args(manifest: &npk::manifest::Manifest) -> (CString, Vec<CString>, Vec<CString>) {
    let init = CString::new(manifest.init.as_ref().unwrap().to_str().unwrap()).unwrap();
    let mut argv = vec![init.clone()];
    if let Some(ref args) = manifest.args {
        for arg in args {
            argv.push(CString::new(arg.as_bytes()).unwrap());
        }
    }

    let mut env = manifest.env.clone().unwrap_or_default();
    env.insert(ENV_NAME.to_string(), manifest.name.to_string());
    env.insert(ENV_VERSION.to_string(), manifest.version.to_string());
    let env = env
        .iter()
        .map(|(k, v)| CString::new(format!("{}={}", k, v)))
        .map(Result::unwrap)
        .collect::<Vec<CString>>();

    (init, argv, env)
}

fn init_signal_handlers() {
    for sig in Signal::iterator()
        .filter(|s| *s != Signal::SIGCHLD)
        .filter(|s| *s != Signal::SIGKILL)
        .filter(|s| *s != Signal::SIGSTOP)
    {
        unsafe {
            let handler = SigHandler::SigAction(forward_signal_to_child);
            let action = SigAction::new(
                handler,
                SaFlags::SA_SIGINFO | SaFlags::SA_RESTART,
                SigSet::empty(),
            );
            sigaction(sig, &action).expect("failed to install sigaction");
        }
    }
}

/// Wrap the Rust log into a AsyncWrite
pub(super) struct Log {
    token: CancellationToken,
    writer: PipeWrite,
}

impl Drop for Log {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

impl Log {
    pub async fn new(level: Level, tag: &str) -> Result<Log, Error> {
        let (reader, writer) = pipe().map_err(|e| Error::io("Failed to open pipe", e))?;
        let token = CancellationToken::new();
        let token_task = token.clone();
        let tag = tag.to_string();
        let async_reader: AsyncPipeRead = reader
            .try_into()
            .map_err(|e| Error::io("Failed to get async handler from pipe reader", e))?;

        task::spawn(async move {
            let mut reader = io::BufReader::new(async_reader).lines();

            loop {
                select! {
                    Ok(Some(line)) = reader.next_line() => {
                        let line = format!("{}: {}", tag, line);
                        match level {
                            Level::Trace => trace!("{}", line),
                            Level::Debug => debug!("{}", line),
                            Level::Info => info!("{}", line),
                            Level::Warn => warn!("{}", line),
                            Level::Error => error!("{}", line),
                        }
                    }
                    _ = token_task.cancelled() => break,
                    else => break,

                }
            }
        });

        Ok(Log { writer, token })
    }
}

// Reset effective caps to the most possible set
fn reset_effective_caps() -> anyhow::Result<()> {
    cdebug!("Resetting effective capabilities");
    caps::set(None, caps::CapSet::Effective, &caps::all())
        .context("Failed to reset effective caps")?;
    Ok(())
}

/// Set uid/gid
fn setid(uid: u32, gid: u32) -> anyhow::Result<()> {
    let rt_priveleged = unistd::geteuid() == Uid::from_raw(0);

    // If running as uid 0 safe our caps across the uid/gid drop
    if rt_priveleged {
        caps::securebits::set_keepcaps(true).context("Failed to set keep caps")?;
    }

    let gid = unistd::Gid::from_raw(gid);
    unistd::setresgid(gid, gid, gid).context("Failed to set resgid")?;

    let uid = unistd::Uid::from_raw(uid);
    unistd::setresuid(uid, uid, uid).context("Failed to set resuid")?;

    if rt_priveleged {
        reset_effective_caps()?;
        caps::securebits::set_keepcaps(false).context("Failed to set keep caps")?;
    }

    Ok(())
}

/// Drop capabilities
fn drop_cap(cs: Option<&HashSet<caps::Capability>>) -> anyhow::Result<()> {
    let mut bounded = caps::read(None, caps::CapSet::Bounding)?;
    if let Some(caps) = cs {
        bounded.retain(|c| !caps.contains(c));
    }

    println!("Dropping capabilities");
    for cap in bounded {
        // caps::set cannot be called for for bounded
        caps::drop(None, caps::CapSet::Bounding, cap)?;
    }

    if let Some(caps) = cs {
        println!("Settings capabilities to {:?}", caps);
        caps::set(None, caps::CapSet::Effective, caps)?;
        caps::set(None, caps::CapSet::Permitted, caps)?;
        caps::set(None, caps::CapSet::Inheritable, caps)?;
        caps::set(None, caps::CapSet::Ambient, caps)?;
    }

    Ok(())
}

/// Spawn a task that waits for the process to exit. This resolves to the exit status
/// of `pid`.
async fn wait(
    container: &Container<IslandProcess>,
    pid: Pid,
    tx: EventTx,
) -> impl Future<Output = Result<ExitStatus, Error>> {
    let container = container.container.clone();
    task::spawn_blocking(move || {
        let pid = unistd::Pid::from_raw(pid as i32);
        let status = loop {
            match sys::wait::waitpid(Some(pid), None) {
                // The process exited normally (as with exit() or returning from main) with the given exit code.
                // This case matches the C macro WIFEXITED(status); the second field is WEXITSTATUS(status).
                Ok(sys::wait::WaitStatus::Exited(pid, code)) => {
                    // There is no way to make the "init" exit with a signal status. Use a defined
                    // offset to get the original signal. This is the sad way everyone does it...
                    if SIGNAL_OFFSET <= code {
                        println!("signal: {}", code - SIGNAL_OFFSET);
                        let signal =
                            Signal::try_from(code - SIGNAL_OFFSET).expect("Invalid signal offset");
                        debug!("Process {} exit status is signal {}", pid, signal);
                        break ExitStatus::Signaled(signal);
                    } else {
                        debug!("Process {} exit code is {}", pid, code);
                        break ExitStatus::Exit(code);
                    }
                }

                // The process was killed by the given signal.
                // The third field indicates whether the signal generated a core dump. This case matches the C macro WIFSIGNALED(status); the last two fields correspond to WTERMSIG(status) and WCOREDUMP(status).
                Ok(sys::wait::WaitStatus::Signaled(pid, signal, _dump)) => {
                    debug!("Process {} exit status is signal {}", pid, signal);
                    break ExitStatus::Signaled(signal);
                }

                // The process is alive, but was stopped by the given signal.
                // This is only reported if WaitPidFlag::WUNTRACED was passed. This case matches the C macro WIFSTOPPED(status); the second field is WSTOPSIG(status).
                Ok(sys::wait::WaitStatus::Stopped(_pid, _signal)) => continue,

                // The traced process was stopped by a PTRACE_EVENT_* event.
                // See nix::sys::ptrace and ptrace(2) for more information. All currently-defined events use SIGTRAP as the signal; the third field is the PTRACE_EVENT_* value of the event.
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Ok(sys::wait::WaitStatus::PtraceEvent(_pid, _signal, _)) => continue,

                // The traced process was stopped by execution of a system call, and PTRACE_O_TRACESYSGOOD is in effect.
                // See ptrace(2) for more information.
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Ok(sys::wait::WaitStatus::PtraceSyscall(_pid)) => continue,

                // The process was previously stopped but has resumed execution after receiving a SIGCONT signal.
                // This is only reported if WaitPidFlag::WCONTINUED was passed. This case matches the C macro WIFCONTINUED(status).
                Ok(sys::wait::WaitStatus::Continued(_pid)) => continue,

                // There are currently no state changes to report in any awaited child process.
                // This is only returned if WaitPidFlag::WNOHANG was used (otherwise wait() or waitpid() would block until there was something to report).
                Ok(sys::wait::WaitStatus::StillAlive) => continue,
                // Retry the waitpid call if waitpid fails with EINTR
                Err(e) if e == nix::Error::Sys(nix::errno::Errno::EINTR) => continue,
                Err(e) => panic!("Failed to waitpid on {}: {}", pid, e),
            }
        };

        // Send notification to main loop
        tx.blocking_send(Event::Exit(container, status.clone()))
            .expect("Internal channel error on main event handle");

        status
    })
    .map_err(|e| Error::io("Task join error", io::Error::new(io::ErrorKind::Other, e)))
}

fn set_pdeath_signal(signal: Signal) -> anyhow::Result<()> {
    #[cfg(target_os = "android")]
    const PR_SET_PDEATHSIG: c_int = 1;
    #[cfg(not(target_os = "android"))]
    use libc::PR_SET_PDEATHSIG;

    let result = unsafe { nix::libc::prctl(PR_SET_PDEATHSIG, signal, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .context("Failed to set PR_SET_PDEATHSIG")
}

fn set_no_new_privs(value: bool) -> anyhow::Result<()> {
    #[cfg(target_os = "android")]
    pub const PR_SET_NO_NEW_PRIVS: c_int = 38;
    #[cfg(not(target_os = "android"))]
    use libc::PR_SET_NO_NEW_PRIVS;

    let result = unsafe { nix::libc::prctl(PR_SET_NO_NEW_PRIVS, value as c_ulong, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .context("Failed to set PR_SET_NO_NEW_PRIVS")
}

#[cfg(target_os = "android")]
pub const PR_SET_NAME: c_int = 15;
#[cfg(not(target_os = "android"))]
use libc::PR_SET_NAME;

fn pr_set_name(name: &str) -> anyhow::Result<()> {
    let cname = CString::new(name).unwrap();
    let result = unsafe { libc::prctl(PR_SET_NAME, cname.as_ptr() as c_ulong, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .context("Failed to set PR_SET_KEEPCAPS")
}

fn reset_signal_handlers() {
    Signal::iterator()
        .filter(|s| *s != Signal::SIGCHLD)
        .filter(|s| *s != Signal::SIGKILL)
        .filter(|s| *s != Signal::SIGSTOP)
        .try_for_each(|s| unsafe { signal(s, SigHandler::SigDfl) }.map(drop))
        .expect("failed to signal");
}

#[cfg(not(target_os = "android"))]
fn clone(flags: CloneFlags, signal: Option<c_int>) -> nix::Result<ForkResult> {
    let combined = flags.bits() | signal.unwrap_or(0);
    let res = unsafe {
        libc::syscall(
            libc::SYS_clone,
            combined,
            std::ptr::null() as *const c_void,
            0u64,
            0u64,
            0u64,
        )
    };

    Errno::result(res).map(|res| match res {
        0 => ForkResult::Child,
        res => ForkResult::Parent {
            child: unistd::Pid::from_raw(res as i32),
        },
    })
}

#[cfg(target_os = "android")]
#[allow(invalid_value)]
fn clone(flags: CloneFlags, signal: Option<c_int>) -> nix::Result<ForkResult> {
    use std::{mem::transmute, ptr::null_mut};
    let combined = flags.bits() | signal.unwrap_or(0);
    let res = unsafe {
        libc::clone(
            transmute::<u64, extern "C" fn(*mut c_void) -> c_int>(0u64),
            null_mut(),
            combined,
            null_mut(),
            0u64,
            0u64,
            0u64,
            0u64,
        )
    };

    Errno::result(res).map(|res| match res {
        0 => ForkResult::Child,
        res => ForkResult::Parent {
            child: unistd::Pid::from_raw(res as i32),
        },
    })
}

static mut CHILD_PID: i32 = -1;

extern "C" fn forward_signal_to_child(signal: c_int, _: *mut siginfo_t, _: *mut c_void) {
    let child_pid = unsafe { CHILD_PID };
    if child_pid >= 0 {
        let child = nix::unistd::Pid::from_raw(child_pid);
        let signal = Signal::try_from(signal).unwrap();
        // Writing to stdout in signal handler is bad. Just left this here
        // for debugging.
        // println!("{}: forwarding {} to {}", getpid(), signal, child);
        kill(child, Some(signal)).expect("failed to kill child");
    } else {
        panic!("CHILD_PID is not set");
    }
}
