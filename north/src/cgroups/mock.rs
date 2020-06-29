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
