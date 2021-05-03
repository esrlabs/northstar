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
    pipe::{ConditionNotify, ConditionWait},
    Event, EventTx, ExitStatus, Launcher, MountedContainer as Container, Pid, Process,
};
use crate::runtime::{island::io::Fd, pipe::Condition};
use async_trait::async_trait;
use futures::{Future, TryFutureExt};
use log::{debug, info, warn};
use nix::{
    errno::Errno,
    sched,
    sys::{
        self,
        signal::{Signal, SIGCHLD},
    },
    unistd,
};
use sched::CloneFlags;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt, os::unix::prelude::AsRawFd};
use task::block_in_place as block;
use tokio::{task, time};

mod clone;
mod init;
mod io;
mod seccomp;
mod utils;

const ENV_NAME: &str = "NAME";
const ENV_VERSION: &str = "VERSION";
const SIGNAL_OFFSET: i32 = 128;

#[derive(Debug, Serialize, Deserialize)]
enum LaunchProtocol {
    Error(String),
    Go,
    Launched,
}

#[derive(Debug)]
pub(super) struct Island {
    tx: EventTx,
    config: Config,
}

pub(super) enum IslandProcess {
    Created {
        pid: Pid,
        exit_status: Box<dyn Future<Output = Result<ExitStatus, Error>> + Unpin + Send + Sync>,
        io: (Option<io::Log>, Option<io::Log>),
        cond_start_notify: ConditionNotify,
        cond_started_wait: ConditionWait,
    },
    Started {
        pid: Pid,
        exit_status: Box<dyn Future<Output = Result<ExitStatus, Error>> + Unpin + Send + Sync>,
        io: (Option<io::Log>, Option<io::Log>),
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
            IslandProcess::Stopped => f.debug_struct("IslandProcess::Stoped").finish(),
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

    async fn shutdown(&mut self) -> Result<(), Error>
    where
        Self: Sized,
    {
        Ok(())
    }

    async fn create(&self, container: &Container<Self::Process>) -> Result<Self::Process, Error> {
        let manifest = &container.manifest;
        let (stdout, stderr, mut fds) = io::from_manifest(manifest).await?;

        // Condition pair to signal the child is cloned by init
        let (cond_cloned_wait, cond_cloned_notify) = Condition::new()
            .map_err(|e| Error::io("Failed to create condition", e))?
            .split();
        fds.insert(cond_cloned_notify.as_raw_fd(), Fd::Inherit);

        // Condition pair to signal the child to start
        let (cond_start_wait, cond_start_notify) = Condition::new()
            .map_err(|e| Error::io("Failed to create condition", e))?
            .split();
        fds.insert(cond_start_wait.as_raw_fd(), Fd::Inherit);

        // Condition pair to signal the runtime from the child that it's started
        let (cond_started_wait, cond_started_notify) = Condition::new()
            .map_err(|e| Error::io("Failed to create condition", e))?
            .split();
        fds.insert(cond_started_notify.as_raw_fd(), Fd::Inherit);

        // Calculating init, argv and env allocates. Do that before `clone`.
        let (init, argv, env) = init::args(manifest);

        debug!("{} init is {:?}", manifest.name, init);
        debug!("{} argv is {:?}", manifest.name, argv);
        debug!("{} env is {:?}", manifest.name, env);

        // Prepare a list of mounts and groups that need to be applied to the child. Prepare the list here
        // to avoid any allocation in the child
        let mounts = init::mounts(&self.config, &container).await?;
        let groups = init::groups(manifest);

        // Clone init
        let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS;
        match block(|| clone::clone(flags, Some(SIGCHLD as i32), None)) {
            Ok(result) => match result {
                unistd::ForkResult::Parent { child } => {
                    debug!("Created {} with pid {}", container.container, child);
                    block(|| {
                        drop(cond_cloned_notify);
                        drop(cond_start_wait);
                        drop(cond_started_notify);
                    });

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
                    let exit_status = Box::new(wait(container, pid, self.tx.clone()).await);

                    block(|| cond_cloned_wait.wait());

                    Ok(IslandProcess::Created {
                        pid,
                        exit_status,
                        io: (stdout, stderr),
                        cond_start_notify,
                        cond_started_wait,
                    })
                }
                unistd::ForkResult::Child => {
                    drop(cond_cloned_wait);
                    drop(cond_start_notify);
                    drop(cond_started_wait);

                    init::init(
                        container,
                        &init,
                        &argv,
                        &env,
                        &mounts,
                        &fds,
                        &groups,
                        cond_cloned_notify,
                        cond_start_wait,
                        cond_started_notify,
                    );
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
            IslandProcess::Stopped { .. } => unreachable!(),
        }
    }

    async fn start(mut self) -> Result<Self, Error> {
        info!("Starting {}", self.pid());
        match self {
            IslandProcess::Created {
                pid,
                exit_status,
                io: _io,
                cond_start_notify,
                cond_started_wait,
            } => {
                block(|| {
                    cond_start_notify.notify();
                    cond_started_wait.wait();
                });

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
        let (pid, mut exit_status, io) = match self {
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
            } => (pid, exit_status, io),
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
            // The process is terminated already. Wait for the waittask to do it's job and resolve exit_status
            Err(nix::Error::Sys(errno)) if errno == Errno::ESRCH => {
                debug!("Process {} already exited. Waiting for status", pid);
                let exit_status = exit_status.await?;
                Ok(exit_status)
            }
            Err(e) => Err(Error::Os(format!("Failed to SIGTERM {}", pid), e)),
        }?;

        if let Some(io) = io.0 {
            io.stop().await?;
        }
        if let Some(io) = io.1 {
            io.stop().await?;
        }

        Ok((IslandProcess::Stopped, exit_status))
    }

    async fn destroy(mut self) -> Result<(), Error> {
        match self {
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
                Err(e) if e == nix::Error::Sys(Errno::EINTR) => continue,
                Err(e) => panic!("Failed to waitpid on {}: {}", pid, e),
            }
        };

        // Send notification to main loop
        tx.blocking_send(Event::Exit(container, status.clone()))
            .expect("Internal channel error on main event handle");

        status
    })
    .map_err(|e| {
        Error::io(
            "Task join error",
            std::io::Error::new(std::io::ErrorKind::Other, e),
        )
    })
}
