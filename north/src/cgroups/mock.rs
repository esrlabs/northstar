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

use crate::EventTx;
use anyhow::{Error, Result};
use log::warn;
use north_common::manifest;

#[derive(Debug)]
pub struct CGroupMem;

#[derive(Debug)]
pub struct CGroupCpu;

#[derive(Debug)]
pub struct CGroups {
    pub mem: Option<CGroupMem>,
    pub cpu: Option<CGroupCpu>,
}

impl CGroups {
    pub async fn new(_name: &str, cgroups: &manifest::CGroups, _tx: EventTx) -> Result<CGroups> {
        let mem = cgroups.mem.as_ref().map(|_| {
            warn!(
                "CGroup memory is not supported on {}",
                env!("VERGEN_TARGET_TRIPLE")
            );
            CGroupMem
        });
        let cpu = cgroups.cpu.as_ref().map(|_| {
            warn!(
                "CGroup cpu is not supported on {}",
                env!("VERGEN_TARGET_TRIPLE")
            );
            CGroupCpu
        });

        Ok(CGroups { mem, cpu })
    }

    pub async fn assign(&self, _pid: u32) -> Result<(), Error> {
        Ok(())
    }

    pub async fn destroy(self) -> Result<(), Error> {
        Ok(())
    }
}
