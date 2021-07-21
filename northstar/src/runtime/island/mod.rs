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

use self::fs::Dev;
use super::{
    config::Config,
    error::Error,
    pipe::{pipe, Condition, ConditionNotify, ConditionWait, PipeRead, PipeWrite, RawFdExt},
    state::{MountedContainer, Process},
    Event, EventTx, ExitStatus, Pid,
};
use crate::npk::manifest::{Capability, Manifest};
use async_trait::async_trait;
use futures::{Future, FutureExt};
use log::{debug, info, warn};
use nix::{
    errno::Errno,
    libc::c_int,
    sched,
    sys::{
        self,
        signal::{sigprocmask, SigSet, SigmaskHow, Signal},
        wait::WaitPidFlag,
    },
    unistd,
};
use sched::CloneFlags;
use std::{
    collections::HashSet,
    convert::TryFrom,
    ffi::{c_void, CString},
    fmt,
    os::unix::io::AsRawFd,
    ptr::null,
};
use sys::wait;
use task::block_in_place as block;
use tokio::{signal, task, time};
use Signal::SIGCHLD;

mod clone;
mod fs;
mod init;
mod io;
mod seccomp;
mod seccomp_profiles;
mod utils;

/// Environment variable name passed to the container with the containers name
const ENV_NAME: &str = "NAME";
/// Environment variable name passed to the container with the containers version
const ENV_VERSION: &str = "VERSION";
/// Offset for signal as exit code encoding
const SIGNAL_OFFSET: i32 = 128;

type Container = MountedContainer;
type ExitStatusFuture = Box<dyn Future<Output = ExitStatus> + Send + Sync + Unpin>;

#[derive(Debug)]
pub(super) struct Island {
    tx: EventTx,
    config: Config,
    /// Used by child process to detect if the parent process has died
    tripwire_read: PipeRead,
    /// Unused writing end of the tripwire pipe. Keep it in Island for a proper close on `shutdown`
    tripwire_write: PipeWrite,
}

pub(super) enum IslandProcess {
    Created {
        pid: Pid,
        exit_status: ExitStatusFuture,
        io: (Option<io::Log>, Option<io::Log>),
        checkpoint: Checkpoint,
        _dev: Dev,
    },
    Started {
        pid: Pid,
        exit_status: ExitStatusFuture,
        io: (Option<io::Log>, Option<io::Log>),
        _dev: Dev,
    },
    Stopped,
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
            IslandProcess::Stopped => f.debug_struct("IslandProcess::Stopped").finish(),
        }
    }
}

impl Island {
    pub async fn start(tx: EventTx, config: Config) -> Result<Self, Error> {
        let (tripwire_read, tripwire_write) =
            block(pipe).map_err(|e| Error::io("Open tripwire pipe", e))?;
        block(|| tripwire_read.set_cloexec(true))
            .map_err(|e| Error::io("Setting cloexec on tripwire fd", e))?;

        Ok(Island {
            tx,
            config,
            tripwire_read,
            tripwire_write,
        })
    }

    pub async fn shutdown(self) -> Result<(), Error> {
        Ok(())
    }

    pub async fn create(&self, container: &Container) -> Result<Box<dyn Process>, Error> {
        let manifest = &container.manifest;
        let (init, argv) = init_argv(manifest);
        let env = env(manifest);
        let (stdout, stderr, mut fds) = io::from_manifest(manifest).await?;
        let (checkpoint_runtime, checkpoint_init) = checkpoints();
        let tripwire = self.tripwire_read.clone();
        let (mounts, dev) = fs::prepare_mounts(&self.config, &container).await?;
        let groups = groups(manifest);
        let capabilities = capabilities(&container);
        let seccomp = seccomp_filter(&container);
        let root = container
            .root
            .canonicalize()
            .expect("Failed to canonicalize root");

        // Do not close child tripwire fd as it will be needed to detect if the runtime process died
        fds.remove(&self.tripwire_read.as_raw_fd());
        let fds = fds.drain().collect::<Vec<_>>();

        debug!("{} init is {:?}", manifest.name, init);
        debug!("{} argv is {:?}", manifest.name, argv);
        debug!("{} env is {:?}", manifest.name, env);

        // Block signals to make sure that a SIGTERM is not sent to init before the child is spawned.
        // init doesn't have any signals handler and the signal would be lost. The child has default handlers
        // and unblocks all signal and terminates in pending ones if needed. This termination is then caught
        // by init...
        signals_block();

        // Clone init
        let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS;
        match clone::clone(flags, Some(SIGCHLD as c_int)) {
            Ok(result) => match result {
                unistd::ForkResult::Parent { child } => {
                    debug!("Created {} with pid {}", container.container, child);

                    // Unblock signals that were block to start init with masked signals
                    signals_unblock();

                    block(|| drop(checkpoint_init));

                    // Close writing part of log forwards if any
                    let stdout = stdout.map(|(log, fd)| {
                        block(|| unistd::close(fd).ok());
                        log
                    });
                    let stderr = stderr.map(|(log, fd)| {
                        block(|| unistd::close(fd).ok());
                        log
                    });
                    let pid = child.as_raw() as Pid;
                    let exit_status = Box::new(waitpid(container, pid, &self.tx));

                    Ok(Box::new(IslandProcess::Created {
                        pid,
                        exit_status,
                        io: (stdout, stderr),
                        checkpoint: checkpoint_runtime,
                        _dev: dev,
                    }))
                }
                unistd::ForkResult::Child => {
                    drop(checkpoint_runtime);

                    init::init(
                        container,
                        &root,
                        &init,
                        &argv,
                        &env,
                        &mounts,
                        &fds,
                        &groups,
                        capabilities,
                        seccomp,
                        checkpoint_init,
                        tripwire,
                    );
                }
            },
            Err(e) => panic!("Fork error: {}", e),
        }
    }
}

#[async_trait]
impl Process for IslandProcess {
    async fn pid(&self) -> Pid {
        match self {
            IslandProcess::Created { pid, .. } => *pid,
            IslandProcess::Started { pid, .. } => *pid,
            IslandProcess::Stopped { .. } => unreachable!(),
        }
    }

    async fn start(self: Box<Self>) -> Result<Box<dyn Process>, Error> {
        info!("Starting {}", self.pid().await);
        match *self {
            IslandProcess::Created {
                pid,
                exit_status,
                io,
                _dev,
                checkpoint,
            } => {
                task::block_in_place(|| {
                    checkpoint.notify().wait();
                });

                Ok(Box::new(IslandProcess::Started {
                    pid,
                    exit_status,
                    io,
                    _dev,
                }))
            }
            _ => unreachable!(),
        }
    }

    /// Send a SIGTERM to the application. If the application does not terminate with a timeout
    /// it is SIGKILLed.
    async fn stop(
        self: Box<Self>,
        timeout: time::Duration,
    ) -> Result<(Box<dyn Process>, ExitStatus), super::error::Error> {
        let (pid, mut exit_status, io) = match *self {
            IslandProcess::Created {
                pid,
                exit_status,
                io,
                ..
            } => (pid, exit_status, io),
            IslandProcess::Started {
                pid,
                exit_status,
                io,
                _dev,
            } => (pid, exit_status, io),
            IslandProcess::Stopped { .. } => unreachable!(),
        };
        debug!("Trying to send SIGTERM to {}", pid);
        let process_group = unistd::Pid::from_raw(-(pid as i32));
        let sigterm = Some(sys::signal::SIGTERM);
        let exit_status = match sys::signal::kill(process_group, sigterm) {
            Ok(_) => {
                match time::timeout(timeout, &mut exit_status).await {
                    Ok(exit_status) => Ok(exit_status),
                    Err(_) => {
                        warn!(
                            "Process {} did not exit within {:?}. Sending SIGKILL...",
                            pid, timeout
                        );
                        // Send SIGKILL if the process did not terminate before timeout
                        let sigkill = Some(sys::signal::SIGKILL);
                        sys::signal::kill(process_group, sigkill)
                            .map_err(|e| Error::Os("Failed to kill process".to_string(), e))?;

                        Ok(exit_status.await)
                    }
                }
            }
            // The process is terminated already. Wait for the waittask to do it's job and resolve exit_status
            Err(nix::Error::Sys(errno)) if errno == Errno::ESRCH => {
                debug!("Process {} already exited. Waiting for status", pid);
                Ok(exit_status.await)
            }
            Err(e) => Err(Error::Os(format!("Failed to SIGTERM {}", process_group), e)),
        }?;

        if let Some(io) = io.0 {
            io.stop().await?;
        }
        if let Some(io) = io.1 {
            io.stop().await?;
        }

        Ok((Box::new(IslandProcess::Stopped), exit_status))
    }

    async fn destroy(self: Box<Self>) -> Result<(), Error> {
        match *self {
            IslandProcess::Created { io, .. } | IslandProcess::Started { io, .. } => {
                if let Some(io) = io.0 {
                    io.stop().await?;
                }
                if let Some(io) = io.1 {
                    io.stop().await?;
                }
                Ok(())
            }
            IslandProcess::Stopped { .. } => Ok(()),
        }
    }
}

/// Spawn a task that waits for the process to exit. Resolves to the exit status of `pid`.
fn waitpid(container: &Container, pid: Pid, tx: &EventTx) -> impl Future<Output = ExitStatus> {
    let container = container.container.clone();
    let tx = tx.clone();

    task::spawn(async move {
        let mut sigchld = signal::unix::signal(signal::unix::SignalKind::child())
            .expect("Failed to set up signal handle for SIGCHLD");

        // Check the status of the process after every SIGCHLD is received
        let exit_status = loop {
            sigchld.recv().await;
            if let Some(exit) = exit_status(pid) {
                break exit;
            }
        };

        drop(
            tx.send(Event::Exit(container.clone(), exit_status.clone()))
                .await,
        );

        exit_status
    })
    .map(|r| r.expect("Task error"))
}

/// Get exit status of process with `pid` or None
fn exit_status(pid: Pid) -> Option<ExitStatus> {
    let pid = unistd::Pid::from_raw(pid as i32);
    match task::block_in_place(|| wait::waitpid(Some(pid), Some(WaitPidFlag::WNOHANG))) {
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
fn init_argv(manifest: &Manifest) -> (CString, Vec<CString>) {
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

    // argv that is passed to execve must start with init
    let argv = if let Some(ref args) = manifest.args {
        let mut argv = Vec::with_capacity(1 + args.len());
        argv.push(init.clone());
        argv.extend({
            args.iter().map(|arg| {
                CString::new(arg.as_bytes())
                    .expect("Invalid arg. This is a bug in the manifest validation")
            })
        });
        argv
    } else {
        vec![init.clone()]
    };

    // argv
    (init, argv)
}

/// Construct the env argument for the containers execve
fn env(manifest: &Manifest) -> Vec<CString> {
    let mut env = Vec::with_capacity(2);
    env.push(
        CString::new(format!("{}={}", ENV_NAME, manifest.name.to_string()))
            .expect("Invalid container name. This is a bug in the manifest validation"),
    );
    env.push(CString::new(format!("{}={}", ENV_VERSION, manifest.version)).unwrap());

    if let Some(ref e) = manifest.env {
        env.extend({
            e.iter().map(|(k, v)| {
                CString::new(format!("{}={}", k, v))
                    .expect("Invalid env. This is a bug in the manifest validation")
            })
        })
    }

    env
}

/// Generate a list of supplementary gids if the groups info can be retrieved. This
/// must happen before the init `clone` because the group information cannot be gathered
/// without `/etc` etc...
fn groups(manifest: &Manifest) -> Vec<u32> {
    if let Some(groups) = manifest.suppl_groups.as_ref() {
        let mut result = Vec::with_capacity(groups.len());
        for group in groups {
            let cgroup = CString::new(group.as_str()).unwrap(); // Check during manifest parsing
            let group_info = task::block_in_place(|| unsafe {
                nix::libc::getgrnam(cgroup.as_ptr() as *const nix::libc::c_char)
            });
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
fn seccomp_filter(container: &Container) -> Option<seccomp::AllowList> {
    if let Some(seccomp) = container.manifest.seccomp.as_ref() {
        return Some(seccomp::seccomp_filter(
            seccomp.profile.as_ref(),
            seccomp.allowlist.as_ref(),
            container.manifest.capabilities.as_ref(),
        ));
    }
    None
}

/// Block all signals of this process and currenty thread
fn signals_block() {
    SigSet::all()
        .thread_block()
        .expect("Failed to set thread signal mask");
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&SigSet::all()), None).unwrap();
}

/// Unblock all signals of this process and currenty thread
fn signals_unblock() {
    SigSet::all()
        .thread_unblock()
        .expect("Failed to set thread signal mask");
    sigprocmask(SigmaskHow::SIG_UNBLOCK, Some(&SigSet::all()), None).unwrap();
}

/// Capability settings applied in init
struct Capabilities {
    bounded: HashSet<Capability>,
    set: HashSet<Capability>,
}

/// Calculate capability sets
fn capabilities(container: &Container) -> Option<Capabilities> {
    let mut bounded =
        caps::read(None, caps::CapSet::Bounding).expect("Failed to read bounding caps");

    container.manifest.capabilities.as_ref().map(|caps| {
        bounded.retain(|c| !caps.contains(c));
        Capabilities {
            bounded,
            set: caps.clone(),
        }
    })
}

#[derive(Clone)]
pub(super) struct Checkpoint(ConditionWait, ConditionNotify);

fn checkpoints() -> (Checkpoint, Checkpoint) {
    let a = Condition::new().expect("Failed to create condition");
    a.set_cloexec();
    let b = Condition::new().expect("Failed to create condition");
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
