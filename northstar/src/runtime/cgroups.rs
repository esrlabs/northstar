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
use log::debug;
use std::path::Path;
use thiserror::Error;
use tokio::io;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Io error: {0}: {1:?}")]
    Io(String, io::Error),
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
pub struct CGroups;

impl CGroups {
    pub(super) async fn new(
        _top_level_dir: &str,
        _tx: EventTx,
        _container: &Container,
        _cgroups: &manifest::cgroups::CGroups,
        _pid: Pid,
    ) -> Result<CGroups, Error> {
        let _hier = cgroups_rs::hierarchies::auto();
        Ok(CGroups {})
    }

    pub async fn destroy(self) {}
}
