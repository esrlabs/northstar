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

use crate::runtime::error::InstallFailure;
use anyhow::{Context, Result};
use async_std::path::Path;

pub use nix::mount::MsFlags as MountFlags;

pub async fn mount(
    source: &Path,
    target: &Path,
    fstype: &str,
    flags: MountFlags,
    data: Option<&str>,
) -> Result<(), InstallFailure> {
    nix::mount::mount(
        Some(source.as_os_str()),
        target.as_os_str(),
        Some(fstype),
        flags,
        data,
    )
    .map_err(|_| {
        InstallFailure::MountError(format!(
            "Failed to mount {} on {}",
            source.display(),
            target.display()
        ))
    })
}

pub async fn unmount(target: &Path) -> Result<()> {
    nix::mount::umount(target.as_os_str()).context(format!("Failed to umount {}", target.display()))
}
