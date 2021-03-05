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

use super::{
    config::Config, device_mapper as dm, device_mapper, key::PublicKey, loopdev::LoopControl,
};
use bitflags::_core::str::Utf8Error;
use floating_duration::TimeAsFloat;
use futures::{future::ready, Future, FutureExt};
use log::{debug, info};
pub use nix::mount::MsFlags as MountFlags;
use npk::{dm_verity::VerityHeader, manifest::Manifest, npk::Npk};
use std::{
    io,
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
    process,
    sync::Arc,
};
use thiserror::Error;
use tokio::{
    fs,
    task::{self, JoinError},
    time,
};

const FS_TYPE: &str = "squashfs";

#[derive(Error, Debug)]
pub enum Error {
    #[error("Device mapper error: {0:?}")]
    DeviceMapper(device_mapper::Error),
    #[error("Loop device error: {0:?}")]
    LoopDevice(super::loopdev::Error),
    #[error("IO error: {0}: {1:?}")]
    Io(String, io::Error),
    #[error("DM Verity error: {0:?}")]
    DmVerity(npk::dm_verity::Error),
    #[error("NPK error: {0:?}")]
    Npk(npk::npk::Error),
    #[error("NPK version mismatch")]
    NpkVersionMismatch,
    #[error("UTF-8 conversion error: {0:?}")]
    Utf8Conversion(Utf8Error),
    #[error("Inotify timeout error {0}")]
    Timeout(String),
    #[error("Task join error: {0}")]
    JoinError(JoinError),
    #[error("Os error: {0}")]
    Os(nix::Error),
    #[error("Repository error: {0:?}")]
    MissingKey(String),
}

#[derive(Debug)]
pub(super) struct MountControl {
    dm: Arc<dm::Dm>,
    lc: Arc<LoopControl>,
    device_mapper_dev: String,
}

impl MountControl {
    pub(super) async fn new(config: &Config) -> Result<MountControl, Error> {
        let lc = LoopControl::open(&config.devices.loop_control, &config.devices.loop_dev)
            .await
            .map_err(Error::LoopDevice)?;
        let dm = dm::Dm::new(&config.devices.device_mapper).map_err(Error::DeviceMapper)?;
        let device_mapper_dev = config.devices.device_mapper_dev.clone();
        Ok(MountControl {
            lc: Arc::new(lc),
            dm: Arc::new(dm),
            device_mapper_dev,
        })
    }

    /// Mounts the npk root fs to target and returns the device used to mount (loopback or device mapper)
    pub(super) async fn mount(
        &self,
        npk: Npk,
        target: &Path,
        key: Option<&PublicKey>,
    ) -> impl Future<Output = Result<PathBuf, Error>> {
        let key = key.copied();
        let dm = self.dm.clone();
        let lc = self.lc.clone();
        let target = target.to_owned();
        let device_mapper_dev = self.device_mapper_dev.clone();

        task::spawn(async move {
            let start = time::Instant::now();

            let manifest = npk.manifest();
            debug!("Mounting {}:{}", manifest.name, manifest.version);
            let use_verity = key.is_some();

            if npk.version() != &Manifest::VERSION {
                return Err(Error::NpkVersionMismatch);
            }
            let manifest = npk.manifest().clone();

            debug!("Loaded manifest of {}:{}", manifest.name, manifest.version);

            let device =
                setup_and_mount(dm, lc, &device_mapper_dev, npk, &target, use_verity).await?;

            let duration = start.elapsed();

            info!(
                "Mounted {}:{} Mounting: {:.03}s",
                manifest.name,
                manifest.version,
                duration.as_fractional_secs(),
            );

            Ok(device)
        })
        .then(|r| match r {
            Ok(r) => ready(r),
            Err(e) => ready(Err(Error::JoinError(e))),
        })
    }

    pub(super) async fn umount(
        &self,
        target: &Path,
        verity_device: Option<&Path>,
    ) -> Result<(), Error> {
        task::block_in_place(|| nix::mount::umount(target).map_err(Error::Os))?;

        if let Some(verity_device) = verity_device {
            debug!("Waiting for dm device {}", verity_device.display());
            wait_for_file_deleted(&verity_device, std::time::Duration::from_secs(5)).await?;
        }

        debug!("Removing mountpoint {}", target.display());
        // Root which is the container version
        fs::remove_dir(&target)
            .await
            .map_err(|e| Error::Io(format!("Failed to remove {}", target.display()), e))?;

        Ok(())
    }
}

async fn setup_and_mount(
    dm: Arc<dm::Dm>,
    lc: Arc<LoopControl>,
    device_mapper_dev: &str,
    npk: Npk,
    target: &Path,
    verity: bool,
) -> Result<PathBuf, Error> {
    let verity_header = npk.verity_header().to_owned();
    let fsimg_offset = npk.fsimg_offset();
    let fsimg_size = npk.fsimg_size();
    let manifest = npk.manifest();
    let name = format!(
        "northstar_{}_{}_{}",
        process::id(),
        manifest.name,
        manifest.version
    );

    // Attach the fs image to a loopback device
    // 1. Find a free loop dev
    // 2. Attach
    let loop_device = lc
        .losetup(npk.as_raw_fd(), fsimg_offset, fsimg_size, true, true)
        .await
        .map_err(Error::LoopDevice)?;

    let device = if !verity {
        // We're done. Use the loop device path e.g. /dev/loop4
        loop_device.path().to_owned()
    } else {
        match (&verity_header, &npk.hashes()) {
            (Some(header), Some(hashes)) => {
                let (major, minor) = loop_device.dev_id();
                let loop_device_id = format!("{}:{}", major, minor);

                debug!("Loop device id is {}", loop_device_id);

                let verity_device = verity_setup(
                    dm.clone(),
                    device_mapper_dev,
                    &loop_device_id,
                    &header,
                    &name,
                    hashes.fs_verity_hash.as_str(),
                    hashes.fs_verity_offset,
                )
                .await?;
                verity_device
            }
            // TODO: Is this correct? No!
            _ => loop_device.path().to_owned(),
        }
    };

    if !target.exists() {
        debug!("Creating mount point {}", target.display());
        fs::create_dir_all(&target).await.map_err(|e| {
            Error::Io(
                format!("Failed to create directory {}", target.display()),
                e,
            )
        })?;
    }

    // Finally mount
    mount(&device, target, &FS_TYPE, MountFlags::MS_RDONLY, None).await?;

    // Set the device to auto-remove once unmounted
    if verity {
        dm.device_remove(
            &name.to_string(),
            &device_mapper::DmOptions::new().set_flags(device_mapper::DmFlags::DM_DEFERRED_REMOVE),
        )
        .await
        .map_err(Error::DeviceMapper)?;
    }

    Ok(device.to_owned())
}

async fn verity_setup(
    dm: Arc<dm::Dm>,
    device_mapper_dev: &str,
    dev: &str,
    verity: &VerityHeader,
    name: &str,
    verity_hash: &str,
    size: u64,
) -> Result<PathBuf, Error> {
    debug!("Creating a read-only verity device (name: {})", &name);
    let start = time::Instant::now();

    let alg_no_pad = std::str::from_utf8(&verity.algorithm[0..VerityHeader::ALGORITHM.len()])
        .map_err(Error::Utf8Conversion)?;
    let hex_salt = hex::encode(&verity.salt[..(verity.salt_size as usize)]);
    let verity_table = format!(
        "{} {} {} {} {} {} {} {} {} {}",
        verity.version,
        dev,
        dev,
        verity.data_block_size,
        verity.hash_block_size,
        verity.data_blocks,
        verity.data_blocks + 1,
        alg_no_pad,
        verity_hash,
        hex_salt
    );
    let table = vec![(0, size / 512, "verity".to_string(), verity_table.clone())];

    debug!("Creating verity device");

    let dm_device = dm
        .device_create(
            &name,
            &dm::DmOptions::new().set_flags(dm::DmFlags::DM_READONLY),
        )
        .await
        .map_err(Error::DeviceMapper)?;
    let dm_dev = PathBuf::from(format!("{}{}", device_mapper_dev, dm_device.id() & 0xFF));

    debug!("Using verity device {}", dm_dev.display());

    dm.table_load_flags(
        name,
        &table,
        dm::DmOptions::new().set_flags(dm::DmFlags::DM_READONLY),
    )
    .await
    .map_err(Error::DeviceMapper)?;

    debug!("Resuming device");
    dm.device_suspend(&name, &dm::DmOptions::new())
        .await
        .map_err(Error::DeviceMapper)?;

    debug!("Waiting for device {}", dm_dev.display());
    while !dm_dev.exists() {
        time::sleep(time::Duration::from_millis(1)).await;
    }

    let veritysetup_duration = start.elapsed();
    debug!(
        "Verity setup took {:.03}s",
        veritysetup_duration.as_fractional_secs()
    );

    Ok(dm_dev)
}

async fn mount(
    dev: &Path,
    target: &Path,
    r#type: &str,
    flags: MountFlags,
    data: Option<&str>,
) -> Result<(), Error> {
    let start = time::Instant::now();
    debug!(
        "Mounting {} fs on {} to {}",
        r#type,
        dev.display(),
        target.display(),
    );
    task::block_in_place(|| {
        nix::mount::mount(Some(dev), target, Some(r#type), flags, data).map_err(Error::Os)
    })?;

    let mount_duration = start.elapsed();
    debug!("Mounting took {:.03}s", mount_duration.as_fractional_secs());

    Ok(())
}

async fn wait_for_file_deleted(path: &Path, timeout: time::Duration) -> Result<(), Error> {
    let wait = async {
        while path.exists() {
            time::sleep(time::Duration::from_millis(1)).await;
        }
        Ok(())
    };
    time::timeout(timeout, wait)
        .await
        .map_err(|_| Error::Timeout(format!("Failed to wait for removal of {}", &path.display())))
        .and_then(|r| r)
}
