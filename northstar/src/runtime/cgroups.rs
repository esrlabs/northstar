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
struct CGroup {
    cgroup: String,
    path: PathBuf,
}

pub async fn init_root_cgroups(config: &config::CGroups) -> Result<(), Error> {
    let mount_point = get_mount_point("cpuset")?;
    let cpuset_root = mount_point.join(get_cgroup_root("cpuset", config));

    debug!("Creating cpuset hierarchy under {}", cpuset_root.display());
    create_if_not_exists(cpuset_root.as_path()).await?;

    tokio::try_join!(
        copy_file("cpuset.cpus", &mount_point, &cpuset_root),
        copy_file("cpuset.mems", &mount_point, &cpuset_root),
    )?;
    Ok(())
}

async fn copy_file(name: &str, src_dir: &Path, dst_dir: &Path) -> Result<(), Error> {
    let file_path = src_dir.join(name);
    // NOTE For some reason using fs::copy here does not work
    let value = fs::read_to_string(&file_path).await.map_err(|e| {
        Error::Io(
            format!("Could not read content of {}", file_path.display(),),
            e,
        )
    })?;
    write(&dst_dir.join(name), &value).await
}

impl CGroup {
    async fn new(cgroup: String, path: &Path, config: &manifest::CGroup) -> Result<CGroup, Error> {
        let path = get_mount_point(&cgroup)?.join(&path);
        create_if_not_exists(&path).await?;

        for (param, value) in config {
            let filename = path.join(format!("{}.{}", &cgroup, param));
            debug!("Setting {} to {}", filename.display(), value);
            write(&filename, &value).await?;
        }

        Ok(CGroup { cgroup, path })
    }

    /// Assign a PID to this cgroup
    async fn assign(&self, pid: u32) -> Result<(), Error> {
        debug!("Assigning {} to {}", pid, self.path.display());
        let tasks = self.path.join(TASKS);
        write(&tasks, &pid.to_string()).await
    }

    /// Destroy the cgroup by removing the dir
    async fn destroy(self) -> Result<(), Error> {
        debug!("Destroying cgroup {}", self.path.display());
        fs::remove_dir(&self.path)
            .await
            .map_err(|e| Error::Destroy(self.path.to_string_lossy().to_string(), e))
    }
}

#[derive(Debug)]
pub struct CGroups(Vec<CGroup>);

impl CGroups {
    pub(crate) async fn new(
        config: &config::CGroups,
        name: &str,
        cgroups: &manifest::CGroups,
        tx: EventTx,
    ) -> Result<CGroups, Error> {
        let mut cgroup_list = Vec::new();
        for (controller, params) in cgroups {
            let path = get_cgroup_root(controller, config).join(name);
            cgroup_list.push(CGroup::new(controller.to_owned(), path.as_path(), params).await?);
        }

        if let Some(cgroup) = cgroup_list.iter().find(|cg| cg.cgroup == "memory") {
            setup_oom_monitor(name, cgroup.path.as_path(), tx).await?;
        }

        Ok(CGroups(cgroup_list))
    }

    pub async fn assign(&self, pid: u32) -> Result<(), Error> {
        for cgroup in &self.0 {
            cgroup.assign(pid).await?;
        }
        Ok(())
    }

    pub async fn destroy(self) -> Result<(), Error> {
        for cgroup in self.0 {
            cgroup.destroy().await?;
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
            .map_err(|e| Error::Io(format!("Failed to create directory {}", path.display()), e))
    } else {
        Ok(())
    }
}

async fn write(path: &Path, value: &str) -> Result<(), Error> {
    fs::write(path, value)
        .await
        .map_err(|e| Error::Io(format!("Failed to write to {}", path.display()), e))
}

fn get_cgroup_root(controller: &str, config: &config::CGroups) -> PathBuf {
    config
        .get(controller)
        .cloned()
        .unwrap_or_else(|| PathBuf::from("north"))
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
