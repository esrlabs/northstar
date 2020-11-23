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

use log::debug;
use std::path::Path;
use thiserror::Error;

use floating_duration::TimeAsFloat;
pub use nix::mount::MsFlags as MountFlags;
use tokio::{task, time};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Mount error: {context}")]
    Mount {
        context: String,
        #[source]
        error: nix::Error,
    },
    #[error("Umount error: {context}")]
    Umount {
        context: String,
        #[source]
        error: nix::Error,
    },
}

pub async fn mount(
    source: &Path,
    target: &Path,
    fstype: &str,
    flags: MountFlags,
    data: Option<&str>,
) -> Result<(), Error> {
    task::block_in_place(|| {
        nix::mount::mount(
            Some(source.as_os_str()),
            target.as_os_str(),
            Some(fstype),
            flags,
            data,
        )
        .map_err(|error| Error::Mount {
            context: format!(
                "Failed to mount {} on {} with flags {:?}",
                source.display(),
                target.display(),
                flags,
            ),
            error,
        })
    })
}

pub async fn unmount(target: &Path) -> Result<(), Error> {
    task::block_in_place(|| {
        nix::mount::umount(target.as_os_str()).map_err(|e| Error::Umount {
            context: format!("Failed to unmount {}", target.display()),
            error: e,
        })
    })
}

pub async fn mount_device(device: &Path, root: &Path, r#type: &str) -> Result<(), super::Error> {
    let start = time::Instant::now();
    debug!(
        "Mount {} fs on {} to {}",
        r#type,
        device.display(),
        root.display(),
    );
    mount(&device, &root, &r#type, MountFlags::MS_RDONLY, None).await?;

    let mount_duration = start.elapsed();
    debug!("Mounting took {:.03}s", mount_duration.as_fractional_secs());

    Ok(())
}
