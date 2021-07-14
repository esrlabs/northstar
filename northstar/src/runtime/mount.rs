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

use super::{key::PublicKey, state::Npk};
use crate::{npk, npk::dm_verity::VerityHeader};
use bitflags::_core::str::Utf8Error;
use devicemapper as dm;
use dm::{DevId, DmFlags, DmName};
use floating_duration::TimeAsFloat;
use futures::{future::ready, Future, FutureExt};
use log::{debug, info, warn};
use loopdev::{LoopControl, LoopDevice};
use nix::libc::EAGAIN;
pub use nix::mount::MsFlags as MountFlags;
use std::{
    fmt, io,
    os::unix::{io::AsRawFd, prelude::RawFd},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};
use thiserror::Error;
use tokio::{
    fs,
    sync::Mutex,
    task::{self, JoinError},
    time,
};

const FS_TYPE: &str = "squashfs";

fn dm_error(err: dm::DmError) -> Error {
    Error::DeviceMapper(format!("Device mapper: {:?}", err))
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Device mapper error: {0}")]
    DeviceMapper(String),
    #[error("IO error: {0}: {1:?}")]
    Io(String, io::Error),
    #[error("DM Verity error: {0:?}")]
    DmVerity(npk::dm_verity::Error),
    #[error("NPK error: {0:?}")]
    Npk(npk::npk::Error),
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
pub(super) enum BlockDevice {
    Loopback(PathBuf),
    Verity(PathBuf, String),
}

pub(super) struct MountControl {
    dm: Arc<dm::DM>,
    lc: Arc<Mutex<LoopControl>>,
}

impl fmt::Debug for MountControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MountControl").finish()
    }
}

impl MountControl {
    pub(super) async fn new() -> Result<MountControl, Error> {
        let lc = LoopControl::open().map_err(|e| Error::Io("Open loop control".into(), e))?;
        let dm = dm::DM::new().map_err(dm_error)?;
        Ok(MountControl {
            lc: Arc::new(Mutex::new(lc)),
            dm: Arc::new(dm),
        })
    }

    /// Mounts the npk root fs to target and returns the device used to mount (loopback or device mapper)
    pub(super) fn mount(
        &self,
        npk: Arc<Npk>,
        target: &Path,
        key: Option<&PublicKey>,
    ) -> impl Future<Output = Result<BlockDevice, Error>> {
        let key = key.copied();
        let dm = self.dm.clone();
        let lc = self.lc.clone();
        let target = target.to_owned();

        task::spawn(async move {
            let start = time::Instant::now();
            let manifest = npk.manifest();

            debug!("Mounting {}:{}", manifest.name, manifest.version);
            let device = attach(&dm, &lc, &npk, &target, key.is_some()).await?;

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
        block_device: &BlockDevice,
    ) -> Result<(), Error> {
        match block_device {
            BlockDevice::Loopback(p) => {
                debug!(
                    "Unmounting loop device {} ({})",
                    target.display(),
                    p.display()
                );
                task::block_in_place(|| nix::mount::umount(target).map_err(Error::Os))
                    .expect("Failed to umount");

                debug!("Removing mountpoint {}", target.display());
                fs::remove_dir(&target)
                    .await
                    .map_err(|e| Error::Io(format!("Failed to remove {}", target.display()), e))?;
            }
            BlockDevice::Verity(device, name) => {
                debug!("Unmounting dm device {} from {}", name, target.display());
                task::block_in_place(|| nix::mount::umount(target).map_err(Error::Os))
                    .expect("Failed to umount");

                debug!("Removing mountpoint {}", target.display());
                fs::remove_dir(&target)
                    .await
                    .map_err(|e| Error::Io(format!("Failed to remove {}", target.display()), e))?;

                task::block_in_place(|| {
                    device_wait(
                        &self.dm,
                        device,
                        Some(&DmName::new(&name).unwrap()),
                        time::Duration::from_secs(5000),
                        false,
                    )
                })?;
            }
        }

        Ok(())
    }
}

async fn attach(
    dm: &dm::DM,
    lc: &Mutex<LoopControl>,
    npk: &Npk,
    target: &Path,
    verity: bool,
) -> Result<BlockDevice, Error> {
    let (loop_device, loop_device_path) = {
        let lc = lc.lock().await;
        task::block_in_place(|| {
            losetup(&lc, npk.as_raw_fd(), npk.fsimg_offset(), npk.fsimg_size())
        })?
    };

    debug!("Loop device id is {}", loop_device_path.display());

    let (device, name): (PathBuf, _) = if verity {
        match (npk.verity_header(), npk.hashes()) {
            (Some(header), Some(hashes)) => task::block_in_place(|| {
                let major = loop_device
                    .major()
                    .map_err(|e| Error::Io("Major number".into(), e))?;
                let minor = loop_device
                    .minor()
                    .map_err(|e| Error::Io("Minor number".into(), e))?;
                let loop_device_id = format!("{}:{}", major, minor);
                dm_setup(
                    dm,
                    &loop_device_id,
                    &header,
                    hashes.fs_verity_hash.as_str(),
                    hashes.fs_verity_offset,
                )
            })
            .map(|(p, n)| (p, Some(n)))?,
            _ => todo!("Container is missing hashes but shall be mounted verified"),
        }
    } else {
        // We're done. Use the loop device path e.g. /dev/loop4
        (loop_device_path, None)
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
    let flags = MountFlags::MS_RDONLY | MountFlags::MS_NODEV | MountFlags::MS_NOSUID;
    debug!(
        "Mounting {} fs on {} to {} with {:?}",
        &FS_TYPE,
        device.display(),
        target.display(),
        flags,
    );
    task::block_in_place(|| {
        nix::mount::mount(
            Some(device.as_path()),
            target,
            Some(FS_TYPE),
            flags,
            Option::<&Path>::None,
        )
        .map_err(Error::Os)
    })?;

    // Set the device to auto-remove once unmounted
    if let Some(ref name) = name {
        dm.device_remove(
            &DevId::Name(&DmName::new(&name).unwrap()),
            &dm::DmOptions::new().set_flags(dm::DmFlags::DM_DEFERRED_REMOVE),
        )
        .map_err(dm_error)?;
    }

    let device = match name {
        Some(name) => BlockDevice::Verity(device.to_owned(), name),
        None => BlockDevice::Loopback(device.to_owned()),
    };

    Ok(device)
}

fn losetup(
    control: &LoopControl,
    fd: RawFd,
    offset: u64,
    sizelimit: u64,
) -> Result<(LoopDevice, PathBuf), Error> {
    let start = time::Instant::now();

    // Lock the loopback control file via fcntl. Sync between multiple northstar instances
    let lock = control.flock()?;

    let (ld, path) = loop {
        let ld = control
            .next_free()
            .map_err(|e| Error::Io("Find free loop dev".into(), e))?;

        let path = ld.path().expect("Invalid loopdev device");
        debug!("Using loop dev {}", path.display());

        match ld
            .with()
            .offset(offset)
            .size_limit(sizelimit)
            .read_only(true)
            .autoclear(true)
            .attach_fd(fd)
        {
            Ok(_) => break Ok((ld, path)),
            Err(e) => match e.raw_os_error() {
                Some(EAGAIN) => continue,
                _ => break Err(e),
            },
        };
    }
    .map_err(|e| Error::Io("Loopback attach".into(), e))?;

    drop(lock);

    if let Err(e) = task::block_in_place(|| ld.set_direct_io(true)) {
        warn!("Failed to enable direct io: {}", e);
    }

    let losetup_duration = start.elapsed();
    debug!(
        "Loopback setup took {:.03}s",
        losetup_duration.as_fractional_secs(),
    );

    Ok((ld, path))
}

fn dm_setup(
    dm: &dm::DM,
    dev: &str,
    verity: &VerityHeader,
    verity_hash: &str,
    size: u64,
) -> Result<(PathBuf, String), Error> {
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
    let table = vec![(0, size / 512, "verity".to_string(), verity_table)];

    let name = uuid::Uuid::new_v4().to_string();

    debug!("Creating verity device {}", name);
    let dm_name = DmName::new(&name).unwrap();
    let dm_device = dm
        .device_create(
            &dm_name,
            None,
            &dm::DmOptions::new().set_flags(dm::DmFlags::DM_READONLY),
        )
        .map_err(dm_error)?;

    let device_id = DevId::Name(dm_device.name());

    debug!("Loading verity table for {}", dm_device.name());
    let dm_device = dm
        .table_load_flags(&device_id, &table, DmFlags::DM_READONLY)
        .map_err(dm_error)?;

    debug!("Resuming device {}", dm_device.name());
    let dm_device = dm
        .device_suspend(&device_id, &dm::DmOptions::new())
        .map_err(dm_error)?;

    #[cfg(not(target_os = "android"))]
    let dm_dev = Path::new("/dev/mapper").join(name.to_string());
    #[cfg(target_os = "android")]
    let dm_dev = PathBuf::from(format!("/dev/block/dm-{}", dm_device.device().minor));

    debug!("Waiting for {}", dm_device.name());
    device_wait(
        &dm,
        dm_dev.as_path(),
        Some(dm_name),
        time::Duration::from_secs(5),
        true,
    )?;

    let duration = start.elapsed().as_fractional_secs();
    debug!("Verity setup took {:.03}s", duration);

    Ok((dm_dev, name))
}

fn device_wait(
    dm: &dm::DM,
    dev: &Path,
    name: Option<&DmName>,
    timeout: time::Duration,
    exists: bool,
) -> Result<(), Error> {
    let start = time::Instant::now();

    if let Some(name) = name {
        debug!("Waiting for dm device {}", dev.display());
        while dm
            .list_devices()
            .expect("Failed to list devices")
            .iter()
            .any(|(n, _, _)| n.as_bytes() == name.as_bytes())
            != exists
        {
            thread::sleep(time::Duration::from_millis(1));
            if start.elapsed() > timeout {
                return Err(Error::Timeout(format!("Waiting for dm device {}", name)));
            }
        }
    }

    debug!("Waiting for block device {}", dev.display());
    while dev.exists() != exists {
        thread::sleep(time::Duration::from_millis(1));
        if start.elapsed() > timeout {
            return Err(Error::Timeout(format!(
                "Waiting for dm device {}",
                dev.display()
            )));
        }
    }

    Ok(())
}

/// Flock on a RawFd
trait Flock {
    fn flock(&self) -> Result<FlockGuard, Error>;
}

impl<T> Flock for T
where
    T: AsRawFd,
{
    fn flock(&self) -> Result<FlockGuard, Error> {
        let fd = self.as_raw_fd();
        task::block_in_place(|| nix::fcntl::flock(fd, nix::fcntl::FlockArg::LockExclusive))
            .map(|_| FlockGuard { fd })
            .map_err(Error::Os)
    }
}

/// Releases flock acquired with `Flock::flock` when dropped
struct FlockGuard {
    fd: RawFd,
}

impl Drop for FlockGuard {
    fn drop(&mut self) {
        nix::fcntl::flock(self.fd, nix::fcntl::FlockArg::Unlock)
            .unwrap_or_else(|_| panic!("Failed to release control lock on {}", self.fd))
    }
}
