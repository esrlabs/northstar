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

use anyhow::Result;

pub mod device_mapper;
pub mod loopdev;

#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod mount;

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub mod mount {
    use anyhow::Result;
    use async_std::path::Path;
    pub enum MountFlags {
        RDONLY,
    }

    pub async fn mount(
        _source: &Path,
        _target: &Path,
        _fstype: &str,
        _flags: MountFlags,
        _data: Option<&str>,
    ) -> Result<()> {
        unimplemented!("mount");
    }

    pub async fn unmount(_target: &Path) -> Result<()> {
        unimplemented!("unmounting");
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub async fn setup() -> Result<()> {
    use anyhow::Context;
    use async_std::path::PathBuf;

    log::debug!("Entering mount namespace");
    let r = unsafe { libc::unshare(libc::CLONE_NEWNS) };
    if r != 0 {
        return Err(anyhow::anyhow!(
            "Failed to unshare: {}",
            std::io::Error::last_os_error()
        ));
    }

    let data = PathBuf::from("/data");

    if data.exists().await {
        // Set mount propagation to PRIVATE on /data
        // Mounting with MS_PRIVATE fails on Android on
        // a non private tree.
        mount::mount(
            &PathBuf::from("/"),
            &PathBuf::from("/data"),
            "ext4",
            mount::MountFlags::PRIVATE,
            None,
        )
        .await
        .context("Failed to set mount propagation type to private on /data")?;
    } else {
        log::warn!("Cannot set mount propagation because it's not implememented for your target");
    }
    Ok(())
}
