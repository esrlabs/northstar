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

use super::{Container, Event, EventTx, ExitStatus, Pid};
use futures::{Future, FutureExt};
use log::debug;
use nix::{sys::wait, unistd};
use std::fmt::Debug;
use thiserror::Error;
use tokio::{io, task};
use wait::WaitStatus;

pub(crate) const ENV_NAME: &str = "NAME";
pub(crate) const ENV_VERSION: &str = "VERSION";

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to start process: {0}")]
    Start(String),
    #[error("Failed to stop process")]
    Stop,
    #[error("Wrong container type: {0}")]
    WrongContainerType(String),
    #[error("Minijail error: {0}")]
    Minijail(#[from] ::minijail::Error),
    #[error("IO error: {0}: {1:?}")]
    Io(String, std::io::Error),
    #[error("OS error: {0}: {1:?}")]
    Os(String, nix::Error),
}

/// Spawn a task that waits for the process to exit. This resolves to the exit status
/// of `pid`.
pub(crate) async fn waitpid(
    container: Container,
    pid: Pid,
    event_handle: EventTx,
) -> impl Future<Output = Result<ExitStatus, Error>> {
    task::spawn_blocking(move || {
        let pid = unistd::Pid::from_raw(pid as i32);
        let status = loop {
            match wait::waitpid(Some(pid), None) {
                // The process exited normally (as with exit() or returning from main) with the given exit code.
                // This case matches the C macro WIFEXITED(status); the second field is WEXITSTATUS(status).
                Ok(WaitStatus::Exited(pid, code)) => {
                    debug!("Process {} exit code is {}", pid, code);
                    break ExitStatus::Exit(code);
                }

                // The process was killed by the given signal.
                // The third field indicates whether the signal generated a core dump. This case matches the C macro WIFSIGNALED(status); the last two fields correspond to WTERMSIG(status) and WCOREDUMP(status).
                Ok(WaitStatus::Signaled(pid, signal, _dump)) => {
                    debug!("Process {} exit status is signal {}", pid, signal);
                    break ExitStatus::Signaled(signal);
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
        };

        // Send notification to main loop
        event_handle
            .blocking_send(Event::Exit(container, status.clone()))
            .expect("Internal channel error on main event handle");

        status
    })
    .then(|f| async {
        f.map_err(|e| {
            Error::Io(
                "Task join error".into(),
                io::Error::new(io::ErrorKind::Other, e),
            )
        })
    })
}
