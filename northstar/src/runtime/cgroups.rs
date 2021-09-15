// Copyright (c) 2019 - 2021 ESRLabs
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

use super::{Container, EventTx, Pid};
use crate::npk::manifest;
use log::{debug, info};
use std::{fmt::Debug, path::Path};
use thiserror::Error;
use tokio::io;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Io error: {0}: {1:?}")]
    Io(String, io::Error),
    #[error("CGroups error: {0}")]
    CGroups(String),
}

/// Create the top level cgroups used by northstar
pub async fn init(dir: &Path) -> Result<(), Error> {
    debug!("Initializing root cgroup");
    cgroups_rs::Cgroup::new(cgroups_rs::hierarchies::auto(), dir);
    Ok(())
}

/// Shutdown the cgroups config by removing the dir
pub async fn shutdown(dir: &Path) -> Result<(), Error> {
    debug!("Shutting down root cgroup");
    cgroups_rs::Cgroup::new(cgroups_rs::hierarchies::auto(), dir)
        .delete()
        .expect("Failed to remove top level cgroup");
    Ok(())
}

#[derive(Debug)]
pub struct CGroups {
    cgroup: cgroups_rs::Cgroup,
}

impl CGroups {
    pub(super) async fn new(
        top_level_dir: &str,
        _tx: EventTx,
        container: &Container,
        config: &manifest::cgroups::CGroups,
        pid: Pid,
    ) -> Result<CGroups, Error> {
        info!("Creating cgroups for {}", container);
        let hierarchy = cgroups_rs::hierarchies::auto();
        let cgroup: cgroups_rs::Cgroup = cgroups_rs::Cgroup::new(
            hierarchy,
            Path::new(top_level_dir).join(container.name().to_str()),
        );
        let resources = cgroups_rs::Resources {
            memory: config.memory.clone().unwrap_or_default(),
            pid: cgroups_rs::PidResources::default(),
            cpu: config.cpu.clone().unwrap_or_default(),
            devices: cgroups_rs::DeviceResources::default(),
            network: cgroups_rs::NetworkResources::default(),
            hugepages: cgroups_rs::HugePageResources::default(),
            blkio: cgroups_rs::BlkIoResources::default(),
        };

        cgroup
            .apply(&resources)
            .map_err(|e| Error::CGroups(e.to_string()))?;

        // If adding the task fails it's a fault of the runtime or it's integration
        // and not of the container
        debug!("Assigning pid {} to cgroups", pid);
        cgroup
            .add_task(cgroups_rs::CgroupPid::from(pid as u64))
            .expect("Failed to assign pid");

        Ok(CGroups { cgroup })
    }

    pub async fn destroy(self) {
        info!("Destroying cgroups");
        self.cgroup.delete().expect("Failed to remove cgroups");
    }
}
