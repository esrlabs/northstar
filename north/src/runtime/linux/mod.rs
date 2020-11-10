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
use log::debug;
use nix::sched;
use thiserror::Error;

pub(super) mod cgroups;
#[allow(unused)]
pub(super) mod device_mapper;
pub(super) mod inotify;
pub(super) mod loopdev;
mod minijail;
pub(super) mod mount;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Mount error")]
    Mount(#[from] mount::Error),
    #[error("Unshare error: {context}")]
    Unshare {
        context: String,
        #[source]
        error: nix::Error,
    },
    #[error("Minijail error")]
    Minijail(#[from] minijail::Error),
}

pub async fn init(config: &Config) -> Result<(), Error> {
    // Set mount propagation to PRIVATE on /data
    // Mounting with MS_PRIVATE fails on Android on
    // a non private tree.
    let unshare_root = &config.devices.unshare_root;
    let fs_type = &config.devices.unshare_fstype;
    mount::mount(
        &unshare_root,
        &unshare_root,
        fs_type,
        mount::MountFlags::MS_PRIVATE,
        None,
    )
    .await
    .map_err(Error::Mount)?;

    // Enter a mount namespace
    debug!("Entering mount namespace");
    sched::unshare(sched::CloneFlags::CLONE_NEWNS).map_err(|error| Error::Unshare {
        context: "Failed to unshare with CLONE_NEWNS".to_string(),
        error,
    })?;

    // Static minijail initialization
    minijail::init().await.map_err(Error::Minijail)
}
