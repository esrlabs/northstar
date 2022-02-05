use super::{key::PublicKey, repository::Npk};
use crate::{
    common::version::Version,
    npk::{dm_verity::VerityHeader, npk::Hashes},
};
use devicemapper::{DevId, DmError, DmName, DmOptions};
use futures::{Future, FutureExt};
use humantime::format_duration;
use log::{debug, warn};
use loopdev::LoopControl;
use std::{
    io,
    os::unix::{io::AsRawFd, prelude::RawFd},
    path::{Path, PathBuf},
    str::Utf8Error,
    sync::Arc,
};
use thiserror::Error;
use tokio::{task, time};

use crate::seccomp::Selinux;
pub use nix::mount::MsFlags as MountFlags;

const FS_TYPE: &str = "squashfs";

#[cfg(not(target_os = "android"))]
const DEVICE_MAPPER_DEV: &str = "/dev/dm-";
#[cfg(target_os = "android")]
const DEVICE_MAPPER_DEV: &str = "/dev/block/dm-";

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}: {1:?}")]
    Io(String, io::Error),
    #[error("Os error: {0}")]
    Os(#[from] nix::Error),
    #[error("Device mapper error: {0:?}")]
    DeviceMapper(#[from] DmError),
    #[error("Loop device error: {0:?}")]
    LoopDevice(#[from] io::Error),
    #[error("NPK error: {0:?}")]
    Npk(&'static str),
    #[error("UTF-8 conversion error: {0:?}")]
    Utf8Conversion(Utf8Error),
    #[error("Timeout error {0}")]
    Timeout(String),
}

pub(super) struct MountControl {
    /// Timeout for dm device setup
    dm_timeout: time::Duration,
    /// Timeout for lo device setup
    lo_timeout: time::Duration,
    /// Device mapper handle
    dm: Arc<devicemapper::DM>,
    /// Loop device control
    lc: Arc<loopdev::LoopControl>,
}

impl std::fmt::Debug for MountControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountControl").finish()
    }
}

impl MountControl {
    pub(super) async fn new(
        dm_timeout: time::Duration,
        lo_timeout: time::Duration,
    ) -> Result<MountControl, Error> {
        debug!("Opening loop control");
        let lc = LoopControl::open()?;
        debug!("Opening device mapper control");
        let dm = devicemapper::DM::new()?;

        let dm_version = dm.version().map(Version::from)?;
        debug!("Device mapper version is {}", dm_version);

        Ok(MountControl {
            dm_timeout,
            lo_timeout,
            lc: Arc::new(lc),
            dm: Arc::new(dm),
        })
    }

    /// Mounts the npk root fs to target and returns the device used to mount (loopback or device mapper)
    pub(super) fn mount(
        &self,
        npk: &Npk,
        target: &Path,
        key: Option<&PublicKey>,
    ) -> impl Future<Output = Result<(), Error>> {
        let dm = self.dm.clone();
        let lc = self.lc.clone();
        let key = key.cloned();
        let target = target.to_owned();
        let fd = npk.as_raw_fd();
        let fsimg_size = npk.fsimg_size();
        let fsimg_offset = npk.fsimg_offset();
        let name = npk.manifest().name.clone();
        let version = npk.manifest().version.clone();
        let verity_header = npk.verity_header().cloned();
        let selinux = npk.manifest().selinux.clone();
        let hashes = npk.hashes().cloned();
        let dm_timeout = self.dm_timeout;
        let lo_timeout = self.lo_timeout;

        task::spawn_blocking(move || {
            let start = time::Instant::now();

            debug!("Mounting {}:{}", name, version);
            mount(
                dm,
                lc,
                fd,
                fsimg_offset,
                fsimg_size,
                &version,
                verity_header,
                selinux,
                hashes,
                &target,
                key.is_some(),
                dm_timeout,
                lo_timeout,
            )?;

            let duration = start.elapsed();
            debug!(
                "Finished mount of {}:{} in {}",
                name,
                version,
                format_duration(duration)
            );

            Ok(())
        })
        .map(|r| match r {
            Ok(r) => r,
            Err(e) => panic!("task error: {}", e),
        })
    }

    /// Umount target
    pub(super) fn umount(target: &Path) -> impl Future<Output = Result<(), Error>> {
        let target = target.to_owned();

        task::spawn_blocking(move || {
            let start = time::Instant::now();

            debug!("Unmounting {}", target.display());
            nix::mount::umount(&target)?;

            debug!("Removing mountpoint {}", target.display());
            std::fs::remove_dir(&target)
                .map_err(|e| Error::Io(format!("failed to remove {}", target.display()), e))?;

            let duration = start.elapsed();
            debug!(
                "Finished umount of {} in {}",
                target.display(),
                format_duration(duration)
            );

            Ok(())
        })
        .map(|r| match r {
            Ok(r) => r,
            Err(e) => panic!("Task error: {}", e),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn mount(
    dm: Arc<devicemapper::DM>,
    lc: Arc<LoopControl>,
    fd: RawFd,
    fsimg_offset: u64,
    fsimg_size: u64,
    version: &Version,
    verity_header: Option<VerityHeader>,
    selinux: Option<Selinux>,
    hashes: Option<Hashes>,
    target: &Path,
    verity: bool,
    dm_timeout: time::Duration,
    lo_timeout: time::Duration,
) -> Result<(), Error> {
    // Acquire a loop device and attach the backing file. This operation is racy because
    // getting the next free index and attaching is not atomic. Retry the operation in a
    // loop until successful or timeout.
    let start = time::Instant::now();

    if !target.exists() {
        debug!("Creating mount point {}", target.display());
        std::fs::create_dir_all(&target).map_err(|e| {
            Error::Io(
                format!("failed to create directory {}", target.display()),
                e,
            )
        })?;
    }

    let loop_device = loop {
        let loop_device = lc.next_free()?;
        if loop_device
            .with()
            .offset(fsimg_offset)
            .size_limit(fsimg_size)
            .read_only(true)
            .autoclear(true)
            .attach_fd(fd)
            .is_ok()
        {
            break loop_device;
        }
        if start.elapsed() > lo_timeout {
            return Err(Error::Timeout("failed to acquire loop device".into()));
        }
    };

    let (device, dm_name) = if !verity {
        // We're done. Use the loop device path e.g. /dev/loop4
        let path = loop_device.path().ok_or_else(|| {
            Error::LoopDevice(io::Error::new(
                io::ErrorKind::Other,
                "failed to get loop device path",
            ))
        })?;
        (path, None)
    } else {
        let name = format!("northstar-{}", nanoid::nanoid!());
        let device = match (&verity_header, hashes) {
            (Some(header), Some(hashes)) => {
                let major = loop_device.major()?;
                let minor = loop_device.minor()?;
                let loop_device_id = format!("{}:{}", major, minor);

                debug!("Using loop device id {}", loop_device_id);

                let verity_device = dmsetup(
                    dm.clone(),
                    &loop_device_id,
                    header,
                    &name,
                    hashes.fs_verity_hash.as_str(),
                    hashes.fs_verity_offset,
                    dm_timeout,
                )?;
                verity_device
            }
            _ => {
                warn!(
                    "Cannot mount {}:{} without verity information from a repository with key",
                    name, version
                );

                // The loopdevice has been attached before. Ensure that it is detached in order
                // to avoid leaking the loop device. If the detach failed something is really
                // broken and probably best is to propagate the error with a panic.
                let path = loop_device.path().ok_or_else(|| {
                    Error::LoopDevice(io::Error::new(
                        io::ErrorKind::Other,
                        "failed to get loop device path",
                    ))
                })?;
                warn!("Detaching {} because of failed dmsetup", path.display());
                loop_device
                    .detach()
                    .expect("failed to detach loopback device");

                return Err(Error::Npk("Missing verity information in NPK"));
            }
        };
        (device, Some(name))
    };

    // Finally mount
    debug!(
        "Mounting {} fs on {} to {}",
        FS_TYPE,
        device.display(),
        target.display(),
    );
    let flags = MountFlags::MS_RDONLY | MountFlags::MS_NOSUID;
    let source = Some(&device);
    let fstype = Some(FS_TYPE);
    let data = if let Some(selinux) = selinux {
        if Path::new("/sys/fs/selinux/enforce").exists() {
            Some(format!("{}{}", "context=", selinux.context.as_str()))
        } else {
            warn!("failed to determine SELinux status of host system. SELinux will not be used for container.");
            None
        }
    } else {
        None
    };
    let data = data.as_deref();
    let mount_result = nix::mount::mount(source, target, fstype, flags, data).map_err(Error::Os);

    if let Err(ref e) = mount_result {
        warn!("failed to mount: {}", e);
    }

    // Set the device to auto-remove. If the above mount operation failed the verity device is removed.
    // If the deferred removal fail the runtime panics in order to avoid leaking the verity device.
    if let Some(ref dm_name) = dm_name {
        debug!("Enabling deferred removal of device {}", dm_name);
        dm.device_remove(
            &DevId::Name(DmName::new(dm_name).map_err(Error::DeviceMapper)?),
            DmOptions::default().set_flags(devicemapper::DmFlags::DM_DEFERRED_REMOVE),
        )?;
    }

    Ok(())
}

fn dmsetup(
    dm: Arc<devicemapper::DM>,
    dev: &str,
    verity: &VerityHeader,
    name: &str,
    verity_hash: &str,
    size: u64,
    timeout: time::Duration,
) -> Result<PathBuf, Error> {
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
    let table = [(0, size / 512, "verity".to_string(), verity_table)];
    let name = DmName::new(name)?;
    let id = DevId::Name(name);

    debug!("Creating verity device {}", name);
    let dm_device = dm.device_create(
        name,
        None,
        DmOptions::default().set_flags(devicemapper::DmFlags::DM_READONLY),
    )?;

    let load = || {
        dm.table_load(
            &id,
            &table,
            DmOptions::default().set_flags(devicemapper::DmFlags::DM_READONLY),
        )?;

        let device = PathBuf::from(format!("{}{}", DEVICE_MAPPER_DEV, dm_device.device().minor));

        debug!("Resuming verity device {}", device.display(),);
        dm.device_suspend(&id, DmOptions::default())?;

        debug!("Waiting for verity device {}", device.display(),);
        while !device.exists() {
            // This code runs on a dedicated blocking thread
            std::thread::sleep(time::Duration::from_millis(1));

            if start.elapsed() > timeout {
                return Err(Error::Timeout(format!(
                    "Timeout while waiting for verity device {}",
                    device.display(),
                )));
            }
        }
        Ok(device)
    };

    let device = match load() {
        Ok(device) => device,
        Err(e) => {
            warn!("failed to setup {}", name);
            debug!("Trying to remove device {}", name);
            if let Err(e) = dm.device_remove(&id, DmOptions::default()) {
                warn!("failed to remove {} with {}", name, e);
            }
            return Err(e);
        }
    };

    let duration = start.elapsed().as_secs_f32();
    debug!(
        "Finishing verity device setup of {} after {:.03}s",
        device.display(),
        duration,
    );

    Ok(device)
}
