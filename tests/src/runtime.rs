// Copyright (c) 2019 - 2020 ESRLabs
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

//! Controls North runtime instances

use crate::{
    process_assert::ProcessAssert,
    util::{CaptureReader, Timeout},
};
use anyhow::{anyhow, Context, Result};
use assert_cmd::cargo::CommandCargoExt;
use log::{error, info};
use std::{
    process::{Child, Command, Stdio},
    time,
};

const TIMEOUT: time::Duration = time::Duration::from_secs(3);

async fn nstar(command: &str) -> Result<()> {
    let command = command.to_owned();
    async_std::task::spawn_blocking(move || {
        let output = Command::cargo_bin("nstar")
            .context("Could not find nstar")?
            .arg(&command)
            .output()?;

        // TODO sometimes the shutdown command won't get a reply
        if command != "shutdown" && !output.status.success() {
            let error_msg = String::from_utf8(output.stderr)?;
            error!("Failed to run nstar {}: {}", command, error_msg);
            Err(anyhow!("Failed to run nstar {}: {}", command, error_msg))
        } else {
            info!("nstar {}: {}", command, String::from_utf8(output.stdout)?);
            Ok(())
        }
    })
    .await
}

/// A running instance of north.
pub struct Runtime {
    child: Child,
    output: CaptureReader,
}

impl Runtime {
    /// Launches an instance of north
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use async_std::prelude::*;
    /// use anyhow::Result;
    /// use tests::runtime::Runtime;
    ///
    /// #[async_std::main]
    /// async fn main() -> Result<()> {
    ///     let north = Runtime::launch().await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn launch() -> Result<Runtime> {
        async move {
            let mut child = Command::cargo_bin("north")
                .context("Could not locate the north binary")?
                .current_dir("..")
                .stdout(Stdio::piped())
                .spawn()
                .context("Could not spawn north")?;

            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| anyhow!("Cannot get stdout of child"))?;
            let mut output = CaptureReader::new(stdout).await;

            output
                .captures("Starting console on localhost:4200")
                .await
                .context("Failed to open north console")?;

            Ok(Runtime { child, output })
        }
        .or_timeout(TIMEOUT)
        .await
        .context("Failed to launch north")?
    }

    pub async fn expect_output(&mut self, regex: &str) -> Result<Vec<String>> {
        self.output
            .captures(regex)
            .await?
            .ok_or_else(|| anyhow!("Pattern not found"))
    }

    pub async fn start(&mut self, name: &str) -> Result<ProcessAssert> {
        async move {
            nstar(&format!("start {}", name)).await?;

            // Get container's pid out north's stdout
            let captures = self
                .output
                .captures(&format!("\\[(\\d+)\\] {}: 1: ", name))
                .await?
                .context(format!("couldn't find {}'s pid", name))?;

            let pid = captures
                .into_iter()
                .nth(1)
                .unwrap()
                .parse::<u64>()
                .context(format!("Could not capture {}'s PID", name))?;

            Ok(ProcessAssert::new(pid))
        }
        .or_timeout(TIMEOUT)
        .await
        .context(format!("Failed to start container {}", name))?
    }

    pub async fn stop(&mut self, container_name: &str) -> Result<()> {
        async move {
            nstar(&format!("stop {}", container_name)).await?;

            // Check that the container stopped
            self.output
                .captures(&format!("Stopped {}", container_name))
                .await
                .context(format!("Failed to wait for {} to stop", container_name))?;

            Ok(())
        }
        .or_timeout(TIMEOUT)
        .await
        .context(format!("Failed to stop container {}", container_name))?
    }

    pub async fn try_stop(&mut self, container_name: &str) -> Result<()> {
        nstar(&format!("stop {}", container_name))
            .or_timeout(TIMEOUT)
            .await
            .context(format!("Failed to stop container {}", container_name))?
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        async move {
            nstar("shutdown").await?;

            // Check that the shutdown request was received
            self.output
                .captures("Shutting down...")
                .await
                .context("Shutdown request was not received")?;

            while let Ok(None) = self.child.try_wait() {
                async_std::task::sleep(std::time::Duration::from_millis(50)).await;
            }

            Ok(())
        }
        .or_timeout(TIMEOUT)
        .await
        .context("Failed to shutdown")?
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            self.child.kill().expect("Could not kill north");
        }
    }
}
