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

use super::{config::debug, process::Error};
use log::{debug, error, info};
use npk::manifest::Manifest;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt},
    process::{Child, Command},
    select, task,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub struct Strace {
    child: Child,
    token: CancellationToken,
}

impl Strace {
    /// Create a new Strace instance by starting strace and attaching it to the pid
    /// of the started application. Forward the stderror of strace to the configured sink.
    pub async fn new(
        strace: &debug::Strace,
        manifest: &Manifest,
        log_dir: &Path,
        pid: u32,
    ) -> Result<Strace, Error> {
        let cmd = if let Some(ref strace) = strace.path {
            strace.as_path()
        } else {
            Path::new("strace")
        };
        let mut child = Command::new(cmd)
            .arg("-p")
            .arg(pid.to_string())
            .args(
                strace
                    .flags
                    .as_ref()
                    .cloned()
                    .unwrap_or_default()
                    .split_whitespace(),
            )
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Io("Failed to spawn strace".into(), e))?;

        let token = CancellationToken::new();

        let stderr = child.stderr.take().ok_or_else(|| {
            Error::Io(
                "Failed to get stderr or strace".into(),
                io::Error::new(io::ErrorKind::Other, ""),
            )
        })?;

        // Wait for strace to inform us that it's attached.
        let mut stderr = io::BufReader::new(stderr).lines();
        stderr
            .next_line()
            .await
            .map_err(|e| Error::Io("Reading strace stderr".into(), e))?;
        let mut stderr = stderr.into_inner();

        match strace.output {
            debug::StraceOutput::File => {
                let mut filename = log_dir.join(format!("strace-{}-{}.log", pid, manifest.name));
                let mut n = 0u32;
                while filename.exists() {
                    n += 1;
                    filename = log_dir.join(format!("strace-{}-{}-{}.log", pid, manifest.name, n));
                }

                info!("Dumping strace output to {}", filename.display());

                let mut file = fs::File::create(&filename)
                    .await
                    .map_err(|e| Error::Io("Failed to create strace log file".into(), e))?;

                let token = token.clone();
                task::spawn(async move {
                    select! {
                        result = tokio::io::copy(&mut stderr, &mut file) => {
                            if let Err(e) = result {
                                error!("Failed to write strace output: {}", e);
                            }
                        }
                        _ = token.cancelled() => (),
                    }
                });
            }
            debug::StraceOutput::Log => {
                let mut stderr = io::BufReader::new(stderr).lines();
                let tag = format!("[strace] {}:", manifest.name);
                let token = token.clone();
                task::spawn(async move {
                    loop {
                        select! {
                            stderr = stderr.next_line() => {
                                match stderr {
                                    Ok(Some(line)) => debug!("{}: {}", tag, line),
                                    Ok(None) => break,
                                    Err(e) => {
                                        error!("Failed to forward strace output: {}", e);
                                        break;
                                    }
                                }
                            }
                            _ = token.cancelled() => break,
                        }
                    }
                });
            }
        }
        Ok(Strace { child, token })
    }

    pub async fn destroy(mut self) -> Result<(), Error> {
        // Stop the strace output forwarding
        self.token.cancel();

        // Stop strace - if not already existed - irgnore any error
        self.child.kill().await.ok();
        // Join strace
        debug!("Joining strace");
        self.child
            .wait()
            .await
            .map_err(|e| Error::Io("Failed to join strace".into(), e))?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct Perf {
    output: PathBuf,
    child: Child,
}

impl Perf {
    pub async fn new(
        perf: &debug::Perf,
        manifest: &Manifest,
        log_dir: &Path,
        pid: u32,
    ) -> Result<Perf, Error> {
        let mut filename = log_dir.join(format!("perf-{}-{}.perf", pid, manifest.name));
        let mut n = 0u32;
        while filename.exists() {
            n += 1;
            filename = log_dir.join(format!("perf-{}-{}-{}.perf", pid, manifest.name, n));
        }

        info!("Dumping perf output to {}", filename.display());

        let cmd = if let Some(ref perf) = perf.path {
            perf.as_path()
        } else {
            Path::new("perf")
        };
        let child = Command::new(cmd)
            .arg("record")
            .arg("-p")
            .arg(pid.to_string())
            .arg("-o")
            .arg(filename.display().to_string())
            .args(
                perf.flags
                    .as_ref()
                    .cloned()
                    .unwrap_or_default()
                    .split_whitespace(),
            )
            .spawn()
            .map_err(|e| Error::Io("Failed to spawn strace".into(), e))?;
        Ok(Perf {
            child,
            output: filename,
        })
    }

    pub async fn destroy(mut self) -> Result<(), Error> {
        self.child.kill().await.ok();
        debug!("Joining perf");
        self.child
            .wait()
            .await
            .map_err(|e| Error::Io("Failed to join perf".into(), e))?;

        Ok(())
    }
}
