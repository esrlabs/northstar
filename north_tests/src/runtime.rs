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
    util::{cargo_bin, CaptureReader},
};
use color_eyre::eyre::{eyre, Error, Result, WrapErr};
use log::{error, info};
use std::{path::Path, process::Stdio};
use tokio::{
    process::{Child, Command},
    time,
    time::timeout,
};

const TIMEOUT: time::Duration = time::Duration::from_secs(3);

async fn nstar(command: &str) -> Result<()> {
    let output = Command::new(cargo_bin("nstar"))
        .arg(&command)
        .output()
        .await?;

    // TODO sometimes the shutdown command won't get a reply
    if command != "shutdown" && !output.status.success() {
        let error_msg = String::from_utf8(output.stderr)?;
        error!("Failed to run nstar {}: {}", command, error_msg);
        Err(eyre!("Failed to run nstar {}: {}", command, error_msg))
    } else {
        info!("nstar {}: {}", command, String::from_utf8(output.stdout)?);
        Ok(())
    }
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
    /// use color_eyre::eyre::Result;
    /// use north_tests::runtime::Runtime;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let north = Runtime::launch().await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn launch() -> Result<Runtime, Error> {
        let launch = async move {
            let mut child = Command::new(cargo_bin("north"))
                .current_dir("..")
                .stdout(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .wrap_err("Could not spawn north")?;

            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| eyre!("Cannot get stdout of child"))?;
            let mut output = CaptureReader::new(stdout).await;

            output
                .captures("Starting console on localhost:4200")
                .await
                .wrap_err("Failed to open north console")?;

            Ok::<Runtime, Error>(Runtime { child, output })
        };

        timeout(TIMEOUT, launch)
            .await
            .wrap_err("launching north timed out")
            .and_then(|result| result)
    }

    pub async fn expect_output(&mut self, regex: &str) -> Result<Vec<String>> {
        let search = self.output.captures(regex);
        timeout(TIMEOUT, search)
            .await
            .wrap_err_with(|| format!("Search for pattern \"{}\" timed out", regex))
            .and_then(|res| res)?
            .ok_or_else(|| eyre!("Pattern not found"))
    }

    pub async fn start(&mut self, name: &str) -> Result<ProcessAssert> {
        let start = async move {
            nstar(&format!("start {}", name)).await?;

            // Get container's pid out north's stdout
            let captures = self
                .output
                .captures(&format!("\\[(\\d+)\\] {}: 1: ", name))
                .await?
                .ok_or_else(|| eyre!("Couldn't find {}'s pid", name))?;

            let pid = captures
                .into_iter()
                .nth(1)
                .unwrap()
                .parse::<u64>()
                .wrap_err(format!("Could not capture {}'s PID", name))?;

            Ok::<ProcessAssert, Error>(ProcessAssert::new(pid))
        };

        timeout(TIMEOUT, start)
            .await
            .wrap_err_with(|| format!("Failed to start container {}", name))
            .and_then(|result| result)
    }

    pub async fn stop(&mut self, container_name: &str) -> Result<()> {
        let stop = async move {
            nstar(&format!("stop {}", container_name)).await?;

            // Check that the container stopped
            self.output
                .captures(&format!("Stopped {}", container_name))
                .await
                .wrap_err(format!("Failed to wait for {} to stop", container_name))?;

            Ok::<(), Error>(())
        };

        timeout(TIMEOUT, stop)
            .await
            .wrap_err_with(|| format!("Failed to stop {}", container_name))
            .and_then(|result| result)
    }

    pub async fn try_stop(&mut self, container_name: &str) -> Result<()> {
        let command = format!("stop {}", container_name);
        timeout(TIMEOUT, nstar(&command))
            .await
            .wrap_err_with(|| format!("Failed to stop {}", container_name))
            .and_then(|result| result)
    }

    pub async fn install(&mut self, npk: &Path) -> Result<()> {
        let command = format!("install {}", npk.display());
        timeout(TIMEOUT, nstar(&command))
            .await
            .wrap_err("Installing npk timed out")
            .and_then(|res| res)
    }

    pub async fn uninstall(&mut self, name: &str, version: &str) -> Result<()> {
        let command = format!("uninstall {} {}", name, version);
        timeout(TIMEOUT, nstar(&command))
            .await
            .wrap_err("Uninstalling npk timed out")
            .and_then(|res| res)
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        let shutdown = async {
            nstar("shutdown").await?;

            // Check that the shutdown request was received
            self.output
                .captures("Shutting down...")
                .await
                .wrap_err("Shutdown request was not received")?;

            self.child.wait().await?;
            Ok::<(), color_eyre::eyre::Error>(())
        };

        timeout(TIMEOUT, shutdown)
            .await
            .wrap_err("Shutting down runtime timed out")
            .and_then(|res| res)
    }
}
