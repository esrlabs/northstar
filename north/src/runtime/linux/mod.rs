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

use super::config::Config;
use anyhow::{Context, Result};
use async_std::path::PathBuf;
use log::debug;
use nix::sched;

pub(super) mod cgroups;
#[allow(unused)]
pub(super) mod device_mapper;
pub(super) mod inotify;
pub(super) mod loopdev;
pub(super) mod mount;

pub async fn init(config: &Config) -> Result<()> {
    // Set mount propagation to PRIVATE on /data
    // Mounting with MS_PRIVATE fails on Android on
    // a non private tree.
    let unshare_root: PathBuf = config.devices.unshare_root.clone().into();
    mount::mount(
        &unshare_root,
        &unshare_root,
        &config.devices.unshare_fstype,
        mount::MountFlags::MS_PRIVATE,
        None,
    )
    .await
    .context("Failed to set mount propagation")?;

    debug!("Entering mount namespace");
    sched::unshare(sched::CloneFlags::CLONE_NEWNS).context("Failed to enter mount namespace")?;

    Ok(())
}
