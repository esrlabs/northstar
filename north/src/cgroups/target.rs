// Copyright (c) 2020 E.S.R.Labs. All rights reserved.
//
// NOTICE:  All information contained herein is, and remains
// the property of E.S.R.Labs and its suppliers, if any.
// The intellectual and technical concepts contained herein are
// proprietary to E.S.R.Labs and its suppliers and may be covered
// by German and Foreign Patents, patents in process, and are protected
// by trade secret or copyright law.
// Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained
// from E.S.R.Labs.

use crate::{Event, EventTx};
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
use north_common::manifest;
use std::time::Duration;

const CGROUP_MEM_MOUNT_POINT: &str = "/dev/memcg/north";
const CGROUP_CPU_MOUNT_POINT: &str = "/dev/cpuctl/north";
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
    pub async fn new(name: &str, cgroup: &manifest::CGroupMem, tx: EventTx) -> Result<CGroupMem> {
        let path = PathBuf::from(CGROUP_MEM_MOUNT_POINT).join(name);
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
    pub async fn new(name: &str, cgroup: &manifest::CGroupCpu) -> Result<CGroupCpu> {
        let path = PathBuf::from(CGROUP_CPU_MOUNT_POINT).join(name);
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
        name: &str,
        cgroups: &manifest::CGroups,
        tx: EventTx,
    ) -> Result<CGroups, Error> {
        let mem = if let Some(ref mem) = cgroups.mem {
            let group = CGroupMem::new(&name, &mem, tx)
                .await
                .context("Failed to create mem cgroup")?;
            Some(group)
        } else {
            None
        };

        let cpu = if let Some(ref cpu) = cgroups.cpu {
            let group = CGroupCpu::new(&name, &cpu)
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
