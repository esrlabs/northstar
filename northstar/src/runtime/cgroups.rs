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

use super::{config, Container, Event, EventTx};
use log::{debug, warn};
use npk::manifest;
use proc_mounts::MountIter;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::{fs, io, select, task, time};

const OOM_CONTROL: &str = "memory.oom_control";
const UNDER_OOM: &str = "under_oom 1";
const TASKS: &str = "tasks";

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

#[derive(Debug)]
pub struct CGroups {
    groups: Vec<PathBuf>,
}

impl CGroups {
    pub(crate) async fn new(
        configuration: &config::CGroups,
        container: &Container,
        cgroups: &manifest::CGroups,
        tx: EventTx,
    ) -> Result<CGroups, Error> {
        let mut groups = Vec::new();

        for (controller, params) in cgroups {
            let mount_point = mount_point(controller)?;
            let subdir = configuration
                .get(controller)
                .ok_or_else(|| Error::UnknownController(controller.into()))?;
            let path = mount_point.join(subdir).join(container.name());

            // Create cgroup
            if !path.exists() {
                debug!("Creating {}", path.display());
                fs::create_dir_all(&path)
                    .await
                    .map_err(|e| Error::Io(format!("Failed to create {}", path.display()), e))?;
            }

            // Apply settings from manifest for this group
            for (param, value) in params {
                let filename = path.join(format!("{}.{}", controller, param));
                debug!("Setting {} to {}", filename.display(), value);
                write(&filename, &value).await?;
            }

            // Start a monitor for the memory controller
            if controller == "memory" {
                memory_monitor(container.clone(), &path, tx.clone()).await?;
            }

            groups.push(path);
        }

        Ok(CGroups { groups })
    }

    pub async fn assign(&self, pid: u32) -> Result<(), Error> {
        for cgroup_dir in &self.groups {
            let tasks = cgroup_dir.join(TASKS);
            debug!("Assigning {} to {}", pid, tasks.display());
            write(&tasks, &pid.to_string()).await?;
        }
        Ok(())
    }

    pub async fn destroy(self) -> Result<(), Error> {
        for cgroup_dir in self.groups {
            debug!("Destroying CGroup {}", cgroup_dir.display());
            fs::remove_dir(&cgroup_dir)
                .await
                .map_err(|e| Error::Destroy(cgroup_dir.display().to_string(), e))?;
        }
        Ok(())
    }
}

/// Monitor the oom_control file from memory cgroups and report
/// a oom condition in case.
async fn memory_monitor(container: Container, path: &Path, tx: EventTx) -> Result<(), Error> {
    // Configure oom
    let oom_control = path.join(OOM_CONTROL);
    write(&oom_control, "1").await?;

    // This task stops when the main loop receiver closes
    task::spawn(async move {
        let mut interval = time::interval(time::Duration::from_millis(500));
        // TODO: Stop this loop when doing a destroy. With this implementation it's not
        // possible to distinguish between a read error and a intentional shutdown
        loop {
            select! {
                result = fs::read_to_string(&oom_control) => {
                    match result {
                        Ok(s) => {
                            if s.lines().any(|l| l == UNDER_OOM) {
                                warn!("Container {} is under OOM!", container);
                                // TODO
                                tx.send(Event::Oom(container)).await.ok();
                                break;
                            }
                        }
                        Err(_) => {
                            debug!("Stopping oom monitor of {}", container);
                            break;
                        }
                    };
                },
                _ = tx.closed() => break,
            };
            interval.tick().await;
        }
    });

    Ok(())
}

async fn write(path: &Path, value: &str) -> Result<(), Error> {
    fs::write(path, value)
        .await
        .map_err(|e| Error::Io(format!("Failed to write to {}", path.display()), e))
}

/// Get the cgroup v1 controller hierarchy mount point
fn mount_point(controller: &str) -> Result<PathBuf, Error> {
    let controller = controller.to_owned();
    MountIter::new()
        .map_err(Error::MountInfo)?
        .filter_map(Result::ok)
        .find(|m| m.fstype == "cgroup" && m.options.contains(&controller))
        .map(|m| m.dest)
        .ok_or(Error::UnknownController(controller))
}
