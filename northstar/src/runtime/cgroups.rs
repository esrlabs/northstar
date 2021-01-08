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

use log::{debug, warn};
use npk::manifest;
use proc_mounts::MountIter;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use tokio::{fs, io, select, task, time};

use super::{config, Event, EventTx};

const OOM_CONTROL: &str = "memory.oom_control";
const UNDER_OOM: &str = "under_oom 1";
const TASKS: &str = "tasks";

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to destroy: {0}: {1:?}")]
    Destroy(String, io::Error),
    #[error("Mount error: {0}: {1:?}")]
    Mount(String, io::Error),
    #[error("Io error: {0}: {1:?}")]
    Io(String, io::Error),
    #[error("Cannot access mount points: {0}")]
    MountPointsNotAccessible(#[source] io::Error),
    #[error("No mount point for cgroup controller {0}")]
    ControllerNotFound(String),
}

#[derive(Debug)]
pub struct CGroups {
    cgroup_paths: Vec<PathBuf>,
}

async fn configure_cgroup(
    path: &Path,
    controller: &str,
    params: &manifest::CGroup,
) -> Result<(), Error> {
    for (param, value) in params {
        let filename = path.join(format!("{}.{}", controller, param));
        debug!("Settings {} to {}", filename.display(), value);
        write(&filename, &value).await?;
    }
    Ok(())
}

impl CGroups {
    pub(crate) async fn new(
        config: &config::CGroups,
        name: &str,
        cgroups: &manifest::CGroups,
        tx: EventTx,
    ) -> Result<CGroups, Error> {
        let mut cgroup_paths = Vec::new();
        for (controller, params) in cgroups {
            let path = cgroup_path(controller, config)?.join(name);
            create_if_not_exists(&path).await?;
            configure_cgroup(&path, controller, params).await?;

            if controller == "memory" {
                setup_oom_monitor(name, &path, tx.clone()).await?;
            }

            cgroup_paths.push(path);
        }

        Ok(CGroups { cgroup_paths })
    }

    pub async fn assign(&self, pid: u32) -> Result<(), Error> {
        for cgroup_dir in &self.cgroup_paths {
            let tasks = cgroup_dir.join(TASKS);
            debug!("Assigning {} to {}", pid, tasks.display());
            write(&tasks, &pid.to_string()).await?;
        }
        Ok(())
    }

    pub async fn destroy(self) -> Result<(), Error> {
        for cgroup_dir in self.cgroup_paths {
            debug!("Destroying cgroup {}", cgroup_dir.display());
            fs::remove_dir(&cgroup_dir)
                .await
                .map_err(|e| Error::Destroy(cgroup_dir.display().to_string(), e))?;
        }
        Ok(())
    }
}

async fn setup_oom_monitor(name: &str, path: &Path, tx: EventTx) -> Result<(), Error> {
    let name = name.to_string();

    // Configure oom
    let oom_control = path.join(OOM_CONTROL);
    write(&oom_control, "1").await?;

    // This task stops when the main loop receiver closes
    task::spawn(async move {
        loop {
            select! {
                result = fs::read_to_string(&oom_control) => {
                    match result {
                        Ok(s) => {
                            if s.lines().any(|l| l == UNDER_OOM) {
                                warn!("Container {} is under OOM!", name);
                                // TODO
                                tx.send(Event::Oom(name)).await.ok();
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("Stopping oom {}: {}", oom_control.display(), e);
                            break;
                        }
                    };
                },
                _ = tx.closed() => { break; }
            };
            time::sleep(Duration::from_millis(500)).await;
        }
    });

    Ok(())
}

async fn create_if_not_exists(path: &Path) -> Result<(), Error> {
    if !path.exists() {
        debug!("Creating {}", path.display());
        fs::create_dir_all(&path)
            .await
            .map_err(|e| Error::Io(format!("Failed to create directory {}", path.display()), e))?;
    }
    Ok(())
}

async fn write(path: &Path, value: &str) -> Result<(), Error> {
    fs::write(path, value)
        .await
        .map_err(|e| Error::Io(format!("Failed to write to {}", path.display()), e))
}

fn cgroup_path(controller: &str, config: &config::CGroups) -> Result<PathBuf, Error> {
    let hierarchy = get_mount_point(controller)?;
    let cgroup_subdir = config
        .get(controller)
        .cloned()
        .unwrap_or_else(|| PathBuf::from("north"));
    Ok(hierarchy.join(cgroup_subdir))
}

/// Get the cgroup v1 controller hierarchy mount point
fn get_mount_point(controller: &str) -> Result<PathBuf, Error> {
    let controller = controller.to_owned();
    MountIter::new()
        .map_err(Error::MountPointsNotAccessible)?
        .filter_map(Result::ok)
        .find(|m| m.fstype == "cgroup" && m.options.contains(&controller))
        .map(|m| m.dest)
        .ok_or(Error::ControllerNotFound(controller))
}
