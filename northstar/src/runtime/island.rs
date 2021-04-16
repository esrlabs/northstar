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
    pipe::{pipe, AsyncPipeRead, PipeRead, PipeSendRecv, PipeWrite},
    Event, EventTx, ExitStatus, Launcher, MountedContainer as Container, Pid, Process,
};
use anyhow::Context;
use async_trait::async_trait;
use futures::{Future, TryFutureExt};
use log::{debug, error, info, trace, warn, Level};
use nix::{
    libc,
    mount::{self, MsFlags},
    sched, sys, unistd,
};
use npk::manifest::{Mount, MountFlag};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    env,
    ffi::CString,
    fmt,
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
};
use tokio::{io, io::AsyncBufReadExt, select, task, time};
use tokio_util::sync::CancellationToken;

const ENV_NAME: &str = "NAME";
const ENV_VERSION: &str = "VERSION";

// libc doesn't specificy PR_SET_PDEATHSIG for android but
// the bionic header include it
#[cfg(target_os = "android")]
const PR_SET_PDEATHSIG: libc::c_int = 1;
#[cfg(not(target_os = "android"))]
const PR_SET_PDEATHSIG: libc::c_int = libc::PR_SET_PDEATHSIG;

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
enum Sequence {
    Error(String),
    ParentReady,
    Go,
}

#[derive(Debug)]
pub struct Island {
    tx: EventTx,
    config: Config,
}

pub struct IslandProcess {
    pid: Pid,
    /// Exit handle of this process
    exit_status: Box<dyn Future<Output = Result<ExitStatus, Error>> + Unpin + Send + Sync>,
    intercom: Option<Intercom>,
    _io: (Option<Log>, Option<Log>),
}

impl fmt::Debug for IslandProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Process").field("pid", &self.pid).finish()
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
        let (parent_com, child_com) = super::pipe::pipe_duplex::<PipeRead, PipeWrite>()
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

        match unsafe { unistd::fork() } {
            Ok(result) => match result {
                unistd::ForkResult::Parent { child } => {
                    let pid = child.as_raw() as Pid;
                    self.parent(container, pid, stdout, stderr, parent_com)
                        .await
                }
                unistd::ForkResult::Child => self.child(container, child_fd_map, child_com),
            },
            Err(e) => panic!("Fork error: {}", e),
        }
    }
}

impl Island {
    async fn parent(
        &self,
        container: &Container<IslandProcess>,
        pid: Pid,
        stdout: Option<Log>,
        stderr: Option<Log>,
        mut intercom: Intercom,
    ) -> Result<IslandProcess, Error> {
        let exit_status = Box::new(Self::parent_waitpid(container, pid, self.tx.clone()).await);

        // Signal the child that we're ready. The child will prepare it's start.
        intercom
            .send(Sequence::ParentReady)
            .expect("Intercom error");

        Ok(IslandProcess {
            pid,
            exit_status,
            _io: (stdout, stderr),
            intercom: Some(intercom),
        })
    }

    fn child(
        &self,
        container: &Container<IslandProcess>,
        mut fds: HashMap<i32, i32>,
        mut intercom: Intercom,
    ) -> ! {
        // Wait until parent is fully set up
        match intercom.recv::<Sequence>().expect("intercom error") {
            Sequence::ParentReady => (),
            _ => unreachable!(),
        }
        cdebug!("Parent is ready");

        // Add intercom to list of fds to preserve
        fds.insert(intercom.0.as_raw_fd(), intercom.0.as_raw_fd());
        fds.insert(intercom.1.as_raw_fd(), intercom.1.as_raw_fd());

        match self.child_init(container, fds) {
            Ok(_) => {
                let pid = std::process::id();
                // execve
                println!("{}: Waiting for go", pid);
                intercom.recv::<Sequence>().expect("intercom error");

                // Make sure to close the intercom fds
                drop(intercom);

                let (init, argv, env) = Self::child_env(&container.manifest);

                println!("{} init: {:?}", pid, init);
                println!("{} argv: {:#?}", pid, argv);
                println!("{} env: {:#?}", pid, env);
                panic!("{}: {:?}", pid, unistd::execve(&init, &argv, &env))
            }
            Err(e) => {
                warn!("Child init error: {:?}", e);
                intercom
                    .send(Sequence::Error(e.to_string()))
                    .expect("intercom error");
                panic!("Child init error: {}", e);
            }
        };
    }

    fn child_init(
        &self,
        container: &Container<IslandProcess>,
        fds: HashMap<i32, i32>,
    ) -> anyhow::Result<()> {
        let manifest = &container.manifest;
        let root = container.root.canonicalize()?;

        // Unshare
        cdebug!("Unsharing CLONE_NEWNS");
        sched::unshare(sched::CloneFlags::CLONE_NEWNS).context("Failed to unshare CLONE_NEWNS")?;
        cdebug!("Unsharing CLONE_NEWPID");
        sched::unshare(sched::CloneFlags::CLONE_NEWPID)
            .context("Failed to unshare CLONE_NEWPID")?;

        // Mount
        self.child_mount(&container).context("Failed to mount")?;

        // Chroot
        cdebug!("Using chroot {}", root.display());
        unistd::chroot(&root).context("Failed to chroot")?;

        // Pwd
        cdebug!("Setting pwd to /");
        env::set_current_dir("/").context("Failed to set cwd to /")?;

        // UID / GID
        cdebug!("Using GID {}", manifest.gid);
        unistd::setgid(unistd::Gid::from_raw(manifest.gid)).context("Failed to set gid")?;
        cdebug!("Using UID {}", manifest.uid);
        unistd::setuid(unistd::Uid::from_raw(manifest.uid)).context("Failed to set uid")?;

        // Set the parent process death signal of the calling process to arg2
        // (either a signal value in the range 1..maxsig, or 0 to clear).
        unsafe { libc::prctl(1, PR_SET_PDEATHSIG) };

        Self::child_fds(fds)?;

        // We cannot use log after here because the fd to logd is closed on Android

        Ok(())
    }

    // Child context
    fn child_env(manifest: &npk::manifest::Manifest) -> (CString, Vec<CString>, Vec<CString>) {
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

    // Child context
    // TODO: Do not close the namespace fds?
    fn child_fds(map: HashMap<i32, i32>) -> anyhow::Result<()> {
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

    /// Spawn a task that waits for the process to exit. This resolves to the exit status
    /// of `pid`.
    async fn parent_waitpid(
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
                        debug!("Process {} exit code is {}", pid, code);
                        break ExitStatus::Exit(code);
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
}

impl Island {
    // TODO: The container could be malformed and the mountpoint might be
    // missing. This is not a fault of the RT so don't expect it.
    // TODO: mount flags: nosuid etc....
    // TODO: /dev mounts from manifest: full or minimal
    fn child_mount(&self, container: &Container<IslandProcess>) -> Result<(), Error> {
        let none = Option::<&str>::None;
        let root = container
            .root
            .canonicalize()
            .map_err(|e| Error::io("Failed to canonicalize root", e))?;
        let uid = container.manifest.uid;
        let gid = container.manifest.gid;

        // /proc
        let source = "/proc";
        let target = root.join("proc");
        let flags = MsFlags::MS_BIND;
        mount::mount(Some(source), &target, none, flags, none)
            .map_err(|e| Error::os("Failed to mount /proc", e))?;
        let flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
        mount::mount(Some(source), &target, none, flags, none)
            .map_err(|e| Error::os("Failed to remount /proc ro", e))?;

        // /dev
        let source = "/dev/";
        let target = root.join("dev");
        mount::mount(Some(source), &target, none, MsFlags::MS_BIND, none)
            .map_err(|e| Error::os("Failed to mount /dev", e))?;

        for (target, mount) in &container.manifest.mounts {
            match &mount {
                Mount::Bind { host, flags } => {
                    if !&host.exists() {
                        cwarn!(
                            "Cannot bind mount nonexitent source {} to {}",
                            host.display(),
                            target.display()
                        );
                        continue;
                    }
                    let rw = flags.contains(&MountFlag::Rw);
                    cdebug!(
                        "Mounting {} on {}{}",
                        host.display(),
                        target.display(),
                        if rw { " (rw)" } else { "" }
                    );
                    let target = root.join_strip(target);
                    mount::mount(Some(host), &target, none, MsFlags::MS_BIND, none).map_err(
                        |e| Error::os(format!("Failed to bind mount {}", target.display()), e),
                    )?;

                    if !rw {
                        let flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
                        mount::mount(Some(host), &target, none, flags, none).map_err(|e| {
                            Error::os(format!("Failed to remount mount {}", target.display()), e)
                        })?;
                    }
                }
                Mount::Persist => {
                    let dir = self.config.data_dir.join(&container.manifest.name);
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
                    mount::mount(Some(&dir), &target, none, MsFlags::MS_BIND, none).map_err(
                        |e| Error::os(format!("Failed to bind mount {}", target.display()), e),
                    )?;
                }
                Mount::Resource { name, version, dir } => {
                    let src = {
                        // Join the source of the resource container with the mount dir
                        let resource_root =
                            self.config.run_dir.join(format!("{}:{}", name, version));
                        let dir = dir
                            .strip_prefix("/")
                            .map(|d| resource_root.join(d))
                            .unwrap_or(resource_root);

                        if !dir.exists() {
                            return Err(Error::StartContainerFailed(
                                container.container.clone(),
                                format!("Resource folder {} is missing", dir.display()),
                            ));
                        }

                        dir
                    };

                    cdebug!("Mounting {} on {}", src.display(), target.display());

                    let target = root.join_strip(target);
                    mount::mount(Some(&src), &target, none, MsFlags::MS_BIND, none).map_err(
                        |e| Error::os(format!("Failed to mount {}", target.display()), e),
                    )?;

                    // Remount ro
                    let flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
                    mount::mount(Some(&src), &target, none, flags, none).map_err(|e| {
                        Error::os(format!("Failed to remount {}", target.display()), e)
                    })?;
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
                        .map_err(|e| {
                            Error::os(format!("Failed to bind mount {}", target.display()), e)
                        })?;
                }
                _ => (),
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Process for IslandProcess {
    fn pid(&self) -> Pid {
        self.pid
    }

    async fn start(&mut self) -> Result<(), Error> {
        info!("Starting {}", self.pid());
        let mut intercom = self.intercom.take().expect("Start called twice");
        intercom.send(Sequence::Go).ok();

        Ok(())
    }

    /// Send a SIGTERM to the application. If the application does not terminate with a timeout
    /// it is SIGKILLed.
    async fn stop(mut self, timeout: time::Duration) -> Result<ExitStatus, super::error::Error> {
        debug!("Trying to send SIGTERM to {}", self.pid);
        let pid = unistd::Pid::from_raw(self.pid as i32);
        let sigterm = Some(sys::signal::SIGTERM);
        let exit_status = match sys::signal::kill(pid, sigterm) {
            Ok(_) => {
                match time::timeout(timeout, &mut self.exit_status).await {
                    Err(_) => {
                        warn!(
                            "Process {} did not exit within {:?}. Sending SIGKILL...",
                            self.pid, timeout
                        );
                        // Send SIGKILL if the process did not terminate before timeout
                        let sigkill = Some(sys::signal::SIGKILL);
                        sys::signal::kill(unistd::Pid::from_raw(self.pid as i32), sigkill)
                            .map_err(|e| Error::Os("Failed to kill process".to_string(), e))?;

                        (&mut self.exit_status).await
                    }
                    Ok(exit_status) => exit_status,
                }
            }
            // The proces is terminated already. Wait for the waittask to do it's job and resolve exit_status
            Err(nix::Error::Sys(errno)) if errno == nix::errno::Errno::ESRCH => {
                debug!("Process {} already exited. Waiting for status", self.pid);
                let exit_status = self.exit_status.await?;
                Ok(exit_status)
            }
            Err(e) => Err(Error::Os(format!("Failed to SIGTERM {}", self.pid), e)),
        }?;

        Ok(exit_status)
    }

    async fn destroy(mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Wrap the Rust log into a AsyncWrite
struct Log {
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
