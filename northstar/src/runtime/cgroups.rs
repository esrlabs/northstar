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

use super::{config, Container, EventTx, Pid};
use crate::npk::manifest;
use thiserror::Error;
use tokio::io;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Io error: {0}: {1:?}")]
    Io(String, io::Error),
}

/// Create the top level cgroups used by northstar
pub async fn init(_configuration: &config::CGroups) -> Result<(), Error> {
    Ok(())
}

/// Shutdown the cgroups config by removing the dir
pub async fn shutdown(_configuration: &config::CGroups) -> Result<(), Error> {
    Ok(())
}

#[derive(Debug)]
pub struct CGroups;

impl CGroups {
    pub(super) async fn new(
        _configuration: &config::CGroups,
        _tx: EventTx,
        _container: &Container,
        _cgroups: &manifest::cgroups::CGroups,
        _pid: Pid,
    ) -> Result<CGroups, Error> {
        Ok(CGroups {})
    }

    pub async fn destroy(self) {}
}
