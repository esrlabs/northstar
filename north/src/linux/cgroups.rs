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

use crate::{
    config, manifest,
    runtime::{Event, EventTx},
};
use anyhow::{anyhow, Context, Error, Result};
use async_std::{
    fs,
    fs::OpenOptions,
    path::{Path, PathBuf},
    prelude::*,
    sync, task,
};
use futures::{future::FutureExt, select};
use log::{debug, warn};
use proc_mounts::MountIter;
use std::time::Duration;

const LIMIT_IN_BYTES: &str = "memory.limit_in_bytes";
const OOM_CONTROL: &str = "memory.oom_control";
const UNDER_OOM: &str = "under_oom 1";
const CPU_SHARES: &str = "cpu.shares";
const TASKS: &str = "tasks";

#[async_trait::async_trait]
trait CGroup: Sized {
    /// Assign a PID to this cgroup
    async fn assign(&self, pid: u32) -> Result<()> {
        if !self.path().exists().await {
            Err(anyhow!("CGroup {} not found", self.path().display()))
        } else {
            debug!("Assigning {} to {}", pid, self.path().display());
            let tasks = self.path().join(TASKS);
            write(&tasks, &pid.to_string()).await
        }
    }

    /// Destroy the cgroup by removing the dir
    async fn destroy(self) -> Result<()> {
        let path = self.path().to_owned();
        if !path.exists().await {
            Err(anyhow!("CGroup {} not found", path.display()))
        } else {
            debug!("Destroying cgroup {}", path.display());
            fs::remove_dir(&path)
                .await
                .with_context(|| format!("Failed to remove {}", path.display()))
        }
    }

    /// Path to this cgroup instance
    fn path(&self) -> &Path;
}

#[derive(Debug)]
pub struct CGroupMem {
    pub path: PathBuf,
    monitor: sync::Sender<()>,
}

impl CGroup for CGroupMem {
    fn path(&self) -> &Path {
        self.path.as_path()
    }
}

impl CGroupMem {
    pub async fn new(
        parent: &Path,
        name: &str,
        cgroup: &manifest::CGroupMem,
        tx: EventTx,
    ) -> Result<CGroupMem> {
        let mount_point =
            get_mount_point("memory").context("Failed to detect cgroups memory mount point")?;
        let path = mount_point.join(parent).join(name);
        create(&path).await?;

        // Configure memory limit
        let limit_in_bytes = path.join(LIMIT_IN_BYTES);
        debug!(
            "Setting {} to {} bytes",
            limit_in_bytes.display(),
            cgroup.limit
        );
        write(&limit_in_bytes, &cgroup.limit.to_string())
            .await
            .with_context(|| {
                format!("Failed to set cgroup limit in {}", limit_in_bytes.display())
            })?;

        // Configure oom
        let oom_control = path.join(OOM_CONTROL);
        write(&oom_control, "1").await.with_context(|| {
            format!(
                "Failed to set cgroup oom control in {}",
                oom_control.display()
            )
        })?;

        // Dropping monitor will stop the task below
        let (monitor, rx) = sync::channel::<()>(1);
        let name = name.to_string();

        task::spawn(async move {
            let mut done = Box::pin(rx.recv()).fuse();

            loop {
                let mut read = Box::pin(fs::read_to_string(&oom_control)).fuse();
                select! {
                    res = read => match res {
                        Ok(s) => {
                            if s.lines().any(|l| l == UNDER_OOM) {
                                warn!("Container {} is under OOM!", name);
                                tx.send(Event::Oom(name)).await;
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("Stopping oom {}: {}", oom_control.display(), e);
                            break;
                        }
                    },
                    _ = done => {
                        debug!("Stopping oom monitor {}", oom_control.display());
                        return;
                    }
                };
                task::sleep(Duration::from_millis(500)).await;
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
    pub async fn new(parent: &Path, name: &str, cgroup: &manifest::CGroupCpu) -> Result<CGroupCpu> {
        let mount_point =
            get_mount_point("cpu").context("Failed to detect cgroups cpu mount point")?;
        let path = mount_point.join(parent).join(name);
        create(&path).await?;

        // Configure cpu shares
        let cpu_shares = path.join(CPU_SHARES);
        debug!(
            "Setting {} to {} shares",
            cpu_shares.display(),
            cgroup.shares
        );
        write(&cpu_shares, &cgroup.shares.to_string())
            .await
            .with_context(|| format!("Failed to set shares in {}", cpu_shares.display()))?;

        Ok(CGroupCpu { path })
    }
}

#[derive(Debug)]
pub struct CGroups {
    pub mem: Option<CGroupMem>,
    pub cpu: Option<CGroupCpu>,
}

impl CGroups {
    pub async fn new(
        config: &config::CGroups,
        name: &str,
        cgroups: &manifest::CGroups,
        tx: EventTx,
    ) -> Result<CGroups, Error> {
        let mem = if let Some(ref mem) = cgroups.mem {
            let parent: PathBuf = config.memory.clone().into();
            let group = CGroupMem::new(&parent, &name, &mem, tx)
                .await
                .context("Failed to create mem cgroup")?;
            Some(group)
        } else {
            None
        };

        let cpu = if let Some(ref cpu) = cgroups.cpu {
            let parent: PathBuf = config.cpu.clone().into();
            let group = CGroupCpu::new(&parent, &name, &cpu)
                .await
                .context("Failed to create cpu cgroup")?;
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

async fn create(path: &Path) -> Result<()> {
    debug!("Creating {}", path.display());
    if !path.exists().await {
        fs::create_dir_all(&path)
            .await
            .with_context(|| format!("Failed to create {}", path.display()))?;
    }
    Ok(())
}

async fn write(path: &Path, value: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .await
        .with_context(|| format!("Failed open {}", path.display()))?;
    file.write_all(format!("{}\n", value).as_bytes())
        .await
        .with_context(|| format!("Failed write to {}", path.display()))?;
    file.sync_all()
        .await
        .with_context(|| format!("Failed sync {}", path.display()))?;
    Ok(())
}

fn get_mount_point(cgroup: &str) -> Result<PathBuf> {
    let cgroup = String::from(cgroup);
    MountIter::new()
        .context("Cannot access mount points")?
        .filter_map(|m| m.ok())
        .find(|m| m.fstype == "cgroup" && m.options.contains(&cgroup))
        .map(|m| m.dest.into())
        .ok_or_else(|| anyhow!("No mount point for cgroup {}", &cgroup))
}
