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

use super::{exit_handle, waitpid, Error, ExitHandleWait, ExitStatus, Pid, ENV_NAME, ENV_VERSION};
use crate::runtime::{npk::Container, EventTx};
use log::debug;
use nix::{sys::signal, unistd};
use std::{process::Child, time};
use tokio::{select, stream::StreamExt, time::sleep};

#[derive(Debug)]
pub struct Process {
    exit_handle_wait: ExitHandleWait,
    child: Child,
}

impl Process {
    pub async fn start(container: &Container, event_tx: EventTx) -> Result<Process, Error> {
        let manifest = &container.manifest;

        // Init
        let init = if let Some(ref init) = manifest.init {
            init.display().to_string()
        } else {
            return Err(Error::WrongContainerType(format!(
                "Cannot start a resource container {}:{}",
                manifest.name, manifest.version,
            )));
        };
        let init = container.root.join(init.trim_start_matches('/'));

        // Command
        let mut cmd = std::process::Command::new(&init);

        // Arguments
        manifest.args.as_ref().map(|args| cmd.args(args));

        // Environment
        let mut env = manifest.env.clone().unwrap_or_default();
        env.insert(ENV_NAME.to_string(), manifest.name.to_string());
        env.insert(ENV_VERSION.to_string(), manifest.version.to_string());
        cmd.envs(env.drain());

        // Spawn
        let child = cmd.spawn().map_err(|e| Error::Io {
            context: format!("Failed to execute {}", init.display()),
            error: e,
        })?;

        let pid = child.id();
        debug!("Started {}", container.manifest.name);

        let (exit_handle_signal, exit_handle_wait) = exit_handle();
        // Spawn a task thats waits for the child to exit
        waitpid(&manifest.name, pid, exit_handle_signal, event_tx).await;

        Ok(Process {
            exit_handle_wait,
            child,
        })
    }
}

#[async_trait::async_trait]
impl super::Process for Process {
    fn pid(&self) -> Pid {
        self.child.id()
    }

    async fn stop(&mut self, timeout: time::Duration) -> Result<ExitStatus, Error> {
        // Send a SIGTERM to the application. If the application does not terminate with a timeout
        // it is SIGKILLed.
        let sigterm = signal::Signal::SIGTERM;
        signal::kill(unistd::Pid::from_raw(self.child.id() as i32), Some(sigterm)).map_err(
            |e| Error::Os {
                context: format!("Failed to SIGTERM {}", self.child.id()),
                error: e,
            },
        )?;

        let timeout = Box::pin(sleep(timeout));
        let exited = Box::pin(self.exit_handle_wait.next());
        let pid = self.child.id();

        Ok(select! {
            s = exited => {
                s.expect("Internal channel error during process termination")  // This is the happy path...
            },
            _ = timeout => {
                signal::kill(unistd::Pid::from_raw(pid as i32), Some(signal::Signal::SIGKILL))
                .map_err(|e| Error::Os { context: "Could not kill process".to_string(), error: e})?;
                ExitStatus::Signaled(signal::Signal::SIGKILL)
            }
        })
    }
}
