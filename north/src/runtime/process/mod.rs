// Copyright (c) 2020 ESRLabs
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

use super::{Event, EventTx};
use async_std::{sync, task};
use async_trait::async_trait;
use futures::StreamExt;
use log::debug;
use nix::{
    sys::{signal, wait},
    unistd,
};
use std::{fmt::Debug, time};
use thiserror::Error;
use wait::WaitStatus;

#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod minijail;
pub mod raw;

const ENV_NAME: &str = "NAME";
const ENV_VERSION: &str = "VERSION";

pub type ExitCode = i32;
pub type Pid = u32;

#[derive(Clone, Debug)]
pub enum ExitStatus {
    /// Process exited with exit code
    Exit(ExitCode),
    /// Process was terminated by a signal
    Signaled(signal::Signal),
}

#[derive(Debug)]
struct ExitHandleWait(sync::Receiver<ExitStatus>);

#[derive(Clone, Debug)]
struct ExitHandleSignal(sync::Sender<ExitStatus>);

impl ExitHandleSignal {
    pub async fn signal(&mut self, status: ExitStatus) {
        self.0.send(status).await
    }
}

#[derive(Debug)]
pub struct ExitHandle {
    signal: ExitHandleSignal,
    wait: ExitHandleWait,
}

impl ExitHandle {
    pub fn new() -> ExitHandle {
        let (tx, rx) = sync::channel(1);
        ExitHandle {
            signal: ExitHandleSignal(tx),
            wait: ExitHandleWait(rx),
        }
    }
    async fn wait(&mut self) -> Option<ExitStatus> {
        self.wait.0.next().await
    }

    fn signal(&self) -> ExitHandleSignal {
        self.signal.clone()
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Problem starting the process: {0}")]
    Start(String),
    #[error("Problem with stopping the process")]
    StopProblem,
    #[error("Wrong container type: {0}")]
    WrongContainerType(String),
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[error("Problem creating a minijail: {0}")]
    Minijail(#[from] ::minijail::Error),
    #[error("IO problem: {context}")]
    Io {
        context: String,
        #[source]
        error: std::io::Error,
    },
    #[error("Linux problem: {context}")]
    LinuxProblem {
        context: String,
        #[source]
        error: nix::Error,
    },
}

#[async_trait]
pub trait Process: Debug + Sync + Send {
    fn pid(&self) -> Pid;
    async fn stop(&mut self, timeout: time::Duration) -> Result<ExitStatus, Error>;
}

/// Spawn a task that waits for the process to exit. Once the process is exited send the return code
// (if any) to the exit_tx handle passed
async fn waitpid(name: &str, pid: u32, mut exit_handle: ExitHandleSignal, event_handle: EventTx) {
    let name = name.to_string();
    task::spawn(async move {
        let status: ExitStatus = task::spawn_blocking(move || {
            let pid = unistd::Pid::from_raw(pid as i32);
            loop {
                let result = wait::waitpid(Some(pid), None);
                debug!("Result of wait_pid is {:?}", result);

                match result {
                    // The process exited normally (as with exit() or returning from main) with the given exit code.
                    // This case matches the C macro WIFEXITED(status); the second field is WEXITSTATUS(status).
                    Ok(WaitStatus::Exited(_pid, code)) => return ExitStatus::Exit(code),

                    // The process was killed by the given signal.
                    // The third field indicates whether the signal generated a core dump. This case matches the C macro WIFSIGNALED(status); the last two fields correspond to WTERMSIG(status) and WCOREDUMP(status).
                    Ok(WaitStatus::Signaled(_pid, signal, _dump)) => {
                        return ExitStatus::Signaled(signal);
                    }

                    // The process is alive, but was stopped by the given signal.
                    // This is only reported if WaitPidFlag::WUNTRACED was passed. This case matches the C macro WIFSTOPPED(status); the second field is WSTOPSIG(status).
                    Ok(WaitStatus::Stopped(_pid, _signal)) => continue,

                    // The traced process was stopped by a PTRACE_EVENT_* event.
                    // See nix::sys::ptrace and ptrace(2) for more information. All currently-defined events use SIGTRAP as the signal; the third field is the PTRACE_EVENT_* value of the event.
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    Ok(WaitStatus::PtraceEvent(_pid, _signal, _)) => continue,

                    // The traced process was stopped by execution of a system call, and PTRACE_O_TRACESYSGOOD is in effect.
                    // See ptrace(2) for more information.
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    Ok(WaitStatus::PtraceSyscall(_pid)) => continue,

                    // The process was previously stopped but has resumed execution after receiving a SIGCONT signal.
                    // This is only reported if WaitPidFlag::WCONTINUED was passed. This case matches the C macro WIFCONTINUED(status).
                    Ok(WaitStatus::Continued(_pid)) => continue,

                    // There are currently no state changes to report in any awaited child process.
                    // This is only returned if WaitPidFlag::WNOHANG was used (otherwise wait() or waitpid() would block until there was something to report).
                    Ok(WaitStatus::StillAlive) => continue,
                    // Retry the waitpid call if waitpid fails with EINTR
                    Err(e) if e == nix::Error::Sys(nix::errno::Errno::EINTR) => continue,
                    Err(e) => panic!("Failed to waitpid on {}: {}", pid, e),
                }
            }
        })
        .await;

        exit_handle.signal(status.clone()).await;
        event_handle
            .send(Event::Exit(name.to_string(), status))
            .await;
    });
}
