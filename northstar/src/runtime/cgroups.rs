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

use super::{config, Container, Event, EventTx, Pid};
use crate::npk::manifest;
use log::{debug, warn};
use proc_mounts::MountIter;
use std::{
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tokio::{
    fs,
    io::{self, AsyncReadExt, AsyncWriteExt},
    select,
    sync::mpsc::error::TrySendError,
    task::{self, JoinHandle},
    time,
};
use tokio_eventfd::EventFd;
use tokio_util::sync::CancellationToken;

const OOM_CONTROL: &str = "memory.oom_control";
const EVENT_CONTROL: &str = "cgroup.event_control";
const TASKS: &str = "tasks";
const CONTROLLER_MEMORY: &str = "memory";

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to destroy: {0}: {1:?}")]
    Destroy(String, io::Error),
    #[error("Io error: {0}: {1:?}")]
    Io(String, io::Error),
    #[error("Failed to read mount info: {0:?}")]
    MountInfo(#[source] io::Error),
    #[error("Unknown cgroup controller {0}")]
    UnknownController(String),
}

/// Create the top level cgroups used by northstar
pub async fn init(configuration: &config::CGroups) -> Result<(), Error> {
    for (controller, dir) in configuration {
        let dir = mount_point(controller)?.join(dir);
        if !dir.exists() {
            debug!("Creating CGroup {}", dir.display());
            fs::create_dir_all(&dir)
                .await
                .map_err(|e| Error::Io(dir.display().to_string(), e))?;
        }
    }
    Ok(())
}

/// Shutdown the cgroups config by removing the dir
pub async fn shutdown(configuration: &config::CGroups) -> Result<(), Error> {
    for (controller, dir) in configuration {
        let dir = mount_point(controller)?.join(dir);
        if dir.exists() {
            debug!("Destroying CGroup {}", dir.display());
            fs::remove_dir(&dir)
                .await
                .map_err(|e| Error::Io(dir.display().to_string(), e))?;
        }
    }
    Ok(())
}

#[derive(Debug)]
enum CGroup {
    /// Generic cgroup controller
    Generic(PathBuf),
    /// Cgroups memory controller with oom monitor
    Memory {
        dir: PathBuf,
        stop: CancellationToken,
        task: JoinHandle<()>,
    },
}

impl CGroup {
    /// Stop and remove cgroup
    async fn destroy(self) {
        let dir = match self {
            CGroup::Generic(dir) => dir,
            CGroup::Memory { dir, stop, task } => {
                debug!("Stopping oom monitor");
                stop.cancel();
                task.await.expect("Task error");
                dir
            }
        };

        debug!("Destroying CGroup {}", dir.display());
        fs::remove_dir(&dir)
            .await
            .unwrap_or_else(|_| panic!("Failed to remove {}", dir.display()));
    }
}

#[derive(Debug)]
pub struct CGroups {
    groups: Vec<CGroup>,
}

impl CGroups {
    pub(super) async fn new(
        configuration: &config::CGroups,
        tx: EventTx,
        container: &Container,
        cgroups: &manifest::CGroups,
        pid: Pid,
    ) -> Result<CGroups, Error> {
        let mut groups = Vec::with_capacity(cgroups.len());

        for (controller, params) in cgroups {
            let mount_point = mount_point(controller)?;
            let subdir = configuration
                .get(controller)
                .ok_or_else(|| Error::UnknownController(controller.to_string()))?;
            let path = mount_point.join(subdir).join(container.name().to_string());

            // Create cgroup
            if !path.exists() {
                debug!("Creating {}", path.display());
                // Expect the path to be creatable
                fs::create_dir_all(&path)
                    .await
                    .unwrap_or_else(|_| panic!("Failed to create {}", path.display()));
            }

            // Apply settings from manifest for this group
            for (param, value) in params {
                let filename = path.join(format!("{}.{}", controller, param));
                debug!("Setting {} to {}", filename.display(), value);
                // If a parameter from the manifest refers to a missing or not writeable file
                // fail.
                if let Err(e) = fs::write(&filename, &value).await {
                    warn!("Failed to write {} to {}", value, filename.display());
                    fs::remove_dir(&path)
                        .await
                        .unwrap_or_else(|_| panic!("Failed to remove {}", path.display()));
                    return Err(Error::Io(
                        format!("Failed to write {} to {}", value, filename.display()),
                        e,
                    ));
                }
            }

            let tasks = path.join(TASKS);
            debug!("Assigning {} to {}", pid, tasks.display());

            fs::write(&tasks, &&pid.to_string().as_bytes())
                .await
                .unwrap_or_else(|_| panic!("Failed to write to {}", path.display()));

            // Start a monitor for the memory controller
            let group = if controller.to_string() == CONTROLLER_MEMORY {
                let (stop, task) = memory_monitor(container.clone(), &path, tx.clone()).await;
                CGroup::Memory {
                    dir: path,
                    stop,
                    task,
                }
            } else {
                CGroup::Generic(path)
            };

            groups.push(group);
        }

        Ok(CGroups { groups })
    }

    pub async fn destroy(self) {
        for group in self.groups {
            group.destroy().await;
        }
    }
}

/// Setup an event fd and oom event listening.
async fn memory_monitor(
    container: Container,
    path: &Path,
    tx: EventTx,
) -> (CancellationToken, JoinHandle<()>) {
    // Configure oom
    let oom_control = path.join(OOM_CONTROL);
    let event_control = path.join(EVENT_CONTROL);
    let stop = CancellationToken::new();

    let mut event_fd = EventFd::new(0, false).expect("Failed to create eventfd");

    debug!("Opening oom_control: {}", oom_control.display());
    let mut oom_control = fs::OpenOptions::new()
        .write(true)
        .open(&oom_control)
        .await
        .expect("Failed to open oom_control");

    debug!("Disabling oom kill in oom_control");
    oom_control
        .write_all(b"1")
        .await
        .expect("Failed to write to oom-control");
    oom_control
        .flush()
        .await
        .expect("Failed to flush oom-control");

    debug!("Opening event_control: {}", event_control.display());
    let mut event_control = fs::OpenOptions::new()
        .write(true)
        .open(&event_control)
        .await
        .expect("Failed to open event_control");
    event_control
        .write_all(format!("{} {}", event_fd.as_raw_fd(), oom_control.as_raw_fd()).as_bytes())
        .await
        .expect("Failed to setup event_control");
    event_control
        .flush()
        .await
        .expect("Failed to setup oom event fd");

    // This task stops when the main loop receiver closes
    let task = {
        let stop = stop.clone();
        task::spawn(async move {
            debug!("Listening for oom events of {}", container);
            let mut buffer = [0u8; 1];

            select! {
                _ = stop.cancelled() => (),
                _ = tx.closed() => (),
                _ = event_fd.read(&mut buffer) => {
                    loop {
                        match tx.try_send(Event::Oom(container.clone())) {
                            Ok(_) => break,
                            Err(TrySendError::Closed(_)) => break,
                            Err(TrySendError::Full(_)) => time::sleep(time::Duration::from_millis(1)).await,
                        }
                    }
                }
            }
            drop(event_fd);
            drop(oom_control);
            drop(event_control);
            debug!("Stopped oom monitor of {}", container);
        })
    };
    (stop, task)
}

/// Get the cgroup v1 controller hierarchy mount point
fn mount_point(controller: &str) -> Result<PathBuf, Error> {
    MountIter::new()
        .map_err(Error::MountInfo)?
        .filter_map(Result::ok)
        .find(|m| m.fstype == "cgroup" && m.options.iter().any(|c| c == controller))
        .map(|m| m.dest)
        .ok_or_else(|| Error::UnknownController(controller.to_string()))
}
