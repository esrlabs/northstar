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
    io::ErrorKind,
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    fs,
    fs::OpenOptions,
    io::{self, AsyncWriteExt},
    select, task, time,
};

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
}

#[derive(Debug)]
struct CGroup {
    cgroup: String,
    path: PathBuf,
}

impl CGroup {
    async fn new(cgroup: String, path: &Path, config: &manifest::CGroup) -> Result<CGroup, Error> {
        let path = get_mount_point(&cgroup)?.join(&path);
        create(&path).await?;

        for (param, value) in config {
            let filename = path.join(format!("{}.{}", &cgroup, param));
            debug!("Setting {} to {} bytes", filename.display(), value);
            write(&filename, &value).await?;
        }

        Ok(CGroup { cgroup, path })
    }

    /// Assign a PID to this cgroup
    async fn assign(&self, pid: u32) -> Result<(), Error> {
        if !self.path.exists() {
            panic!("Failed to find cgroup {}", self.path.display());
        } else {
            debug!("Assigning {} to {}", pid, self.path.display());
            let tasks = self.path.join(TASKS);
            write(&tasks, &pid.to_string()).await
        }
    }

    /// Destroy the cgroup by removing the dir
    async fn destroy(self) -> Result<(), Error> {
        let path = self.path.to_owned();
        if !path.exists() {
            panic!("Failed to find cgroup {}", self.path.display());
        } else {
            debug!("Destroying cgroup {}", path.display());
            fs::remove_dir(&path)
                .await
                .map_err(|e| Error::Destroy(format!("Failed to remove {}", path.display()), e))
        }
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
        for (cgroup_name, values) in cgroups {
            let path = get_cgroup_path(cgroup_name, &config).join(name);
            let cgroup = CGroup::new(cgroup_name.to_owned(), path.as_path(), values).await?;
            cgroup_list.push(cgroup);
        }

        // TODO integrate this into they CGroup type
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

fn get_cgroup_path(name: &str, config: &config::CGroups) -> PathBuf {
    match name {
        "memory" => config.memory.clone(),
        "cpu" => config.cpu.clone(),
        _ => PathBuf::from("north"),
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

async fn create(path: &Path) -> Result<(), Error> {
    debug!("Creating {}", path.display());
    if !path.exists() {
        fs::create_dir_all(&path)
            .await
            .map_err(|e| Error::Io(format!("Failed to create {}", path.display()), e))?;
    }
    Ok(())
}

async fn write(path: &Path, value: &str) -> Result<(), Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .await
        .map_err(|e| Error::Io(format!("Failed open {}", path.display()), e))?;
    file.write_all(format!("{}\n", value).as_bytes())
        .await
        .map_err(|e| Error::Io(format!("Failed write to {}", path.display()), e))?;
    file.sync_all()
        .await
        .map_err(|e| Error::Io(format!("Failed synd {}", path.display()), e))?;
    Ok(())
}

fn get_mount_point(cgroup: &str) -> Result<PathBuf, Error> {
    let cgroup = String::from(cgroup);
    MountIter::new()
        .map_err(|e| Error::Mount("Failed to access mount points".to_string(), e))?
        .filter_map(|m| m.ok())
        .find(|m| m.fstype == "cgroup" && m.options.contains(&cgroup))
        .map(|m| m.dest)
        .ok_or_else(|| {
            Error::Mount(
                format!("No mount point for cgroup {}", &cgroup),
                io::Error::new(ErrorKind::Other, ""),
            )
        })
}
