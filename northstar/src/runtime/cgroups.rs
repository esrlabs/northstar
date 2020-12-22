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
use sync::mpsc;
use thiserror::Error;
use tokio::{fs, fs::OpenOptions, io, prelude::*, select, sync, task, time};

use super::{config, Event, EventTx};

const LIMIT_IN_BYTES: &str = "memory.limit_in_bytes";
const OOM_CONTROL: &str = "memory.oom_control";
const UNDER_OOM: &str = "under_oom 1";
const CPU_SHARES: &str = "cpu.shares";
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

#[async_trait::async_trait]
trait CGroup: Sized {
    /// Assign a PID to this cgroup
    async fn assign(&self, pid: u32) -> Result<(), Error> {
        if !self.path().exists() {
            panic!("Failed to find cgroup {}", self.path().display());
        } else {
            debug!("Assigning {} to {}", pid, self.path().display());
            let tasks = self.path().join(TASKS);
            write(&tasks, &pid.to_string()).await
        }
    }

    /// Destroy the cgroup by removing the dir
    async fn destroy(self) -> Result<(), Error> {
        let path = self.path().to_owned();
        if !path.exists() {
            panic!("Failed to find cgroup {}", self.path().display());
        } else {
            debug!("Destroying cgroup {}", path.display());
            fs::remove_dir(&path)
                .await
                .map_err(|e| Error::Destroy(format!("Failed to remove {}", path.display()), e))
        }
    }

    /// Path to this cgroup instance
    fn path(&self) -> &Path;
}

#[derive(Debug)]
pub struct CGroupMem {
    pub path: PathBuf,
    monitor: mpsc::Sender<()>,
}

impl CGroup for CGroupMem {
    fn path(&self) -> &Path {
        self.path.as_path()
    }
}

impl CGroupMem {
    async fn new(
        parent: &Path,
        name: &str,
        cgroup: &manifest::CGroupMem,
        tx: EventTx,
    ) -> Result<CGroupMem, Error> {
        let mount_point = get_mount_point("memory")?;
        let path = mount_point.join(parent).join(name);
        create(&path).await?;

        // Configure memory limit
        let limit_in_bytes = path.join(LIMIT_IN_BYTES);
        debug!(
            "Setting {} to {} bytes",
            limit_in_bytes.display(),
            cgroup.limit
        );
        write(&limit_in_bytes, &cgroup.limit.to_string()).await?;

        // Configure oom
        let oom_control = path.join(OOM_CONTROL);
        write(&oom_control, "1").await?;

        // Dropping monitor will stop the task below
        let (monitor, mut rx) = mpsc::channel::<()>(1);
        let name = name.to_string();

        task::spawn(async move {
            let mut done = Box::pin(rx.recv());

            loop {
                let read = Box::pin(fs::read_to_string(&oom_control));
                select! {
                    res = read => match res {
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
                    },
                    _ = &mut done => {
                        debug!("Stopping oom monitor {}", oom_control.display());
                        return;
                    }
                };
                time::sleep(Duration::from_millis(500)).await;
            }
        });

        debug!("Created {}", path.display());
        Ok(CGroupMem { path, monitor })
    }
}

#[derive(Debug)]
pub struct CGroupCpu {
    pub path: PathBuf,
}

impl CGroup for CGroupCpu {
    fn path(&self) -> &Path {
        self.path.as_path()
    }
}

impl CGroupCpu {
    async fn new(
        parent: &Path,
        name: &str,
        cgroup: &manifest::CGroupCpu,
    ) -> Result<CGroupCpu, Error> {
        let mount_point = get_mount_point("cpu")?;
        let path = mount_point.join(parent).join(name);
        create(&path).await?;

        // Configure cpu shares
        let cpu_shares = path.join(CPU_SHARES);
        debug!(
            "Setting {} to {} shares",
            cpu_shares.display(),
            cgroup.shares
        );
        write(&cpu_shares, &cgroup.shares.to_string()).await?;

        Ok(CGroupCpu { path })
    }
}

#[derive(Debug)]
pub struct CGroups {
    pub mem: Option<CGroupMem>,
    pub cpu: Option<CGroupCpu>,
}

impl CGroups {
    pub(super) async fn new(
        config: &config::CGroups,
        name: &str,
        cgroups: &manifest::CGroups,
        tx: EventTx,
    ) -> Result<CGroups, Error> {
        let mem = if let Some(ref mem) = cgroups.mem {
            let parent = &config.memory;
            let group = CGroupMem::new(parent, &name, &mem, tx).await?;
            Some(group)
        } else {
            None
        };

        let cpu = if let Some(ref cpu) = cgroups.cpu {
            let parent = &config.cpu;
            let group = CGroupCpu::new(&parent, &name, &cpu).await?;
            Some(group)
        } else {
            None
        };

        Ok(CGroups { mem, cpu })
    }

    pub async fn assign(&self, pid: u32) -> Result<(), Error> {
        if let Some(ref mem) = self.mem {
            mem.assign(pid).await?;
        }
        if let Some(ref cpu) = self.cpu {
            cpu.assign(pid).await?;
        }
        Ok(())
    }

    pub async fn destroy(self) -> Result<(), Error> {
        if let Some(mem) = self.mem {
            mem.destroy().await?;
        }
        if let Some(cpu) = self.cpu {
            cpu.destroy().await?;
        }
        Ok(())
    }
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
