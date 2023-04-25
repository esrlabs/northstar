use crate::{
    api::model::NonNulString,
    common::container::Container,
    npk::{dm_verity::VerityHeader, npk::Hashes},
    runtime::{
        devicemapper::{self, verity::DmVerityHashAlgorithm},
        key::PublicKey,
        repository::Npk,
    },
};
use anyhow::{anyhow, bail, Context, Result};
use futures::{Future, FutureExt};
use log::{debug, warn};
use loopdev::{LoopControl, LoopDevice};
use nix::libc::{EAGAIN, EBUSY};
use std::{
    fs,
    os::unix::{io::AsRawFd, prelude::RawFd},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{task, time};

pub use nix::mount::MsFlags as MountFlags;

const FS_TYPE: &str = "squashfs";

/// Mount metadata.
struct Mount<'a> {
    container: &'a Container,
    fd: RawFd,
    fsimg_offset: u64,
    fsimg_size: u64,
    verity_header: Option<&'a VerityHeader>,
    selinux_context: Option<&'a NonNulString>,
    hashes: Option<&'a Hashes>,
    target: &'a Path,
    key: Option<&'a PublicKey>,
    lo_timeout: Duration,
}

pub(super) struct MountControl {
    /// Timeout for lo device setup
    lo_timeout: time::Duration,
    /// Device mapper handle
    dm: Arc<devicemapper::DeviceMapper>,
    /// Loop device control
    lc: Arc<Mutex<loopdev::LoopControl>>,
}

impl std::fmt::Debug for MountControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountControl").finish()
    }
}

impl MountControl {
    pub(super) async fn new(lo_timeout: time::Duration) -> Result<MountControl> {
        debug!("Opening loop control");
        let lc = LoopControl::open().context("failed to open loop control")?;
        debug!("Opening device mapper control");
        let dm = devicemapper::DeviceMapper::new().context("failed to open device mapper")?;

        Ok(MountControl {
            lo_timeout,
            lc: Arc::new(Mutex::new(lc)),
            dm: Arc::new(dm),
        })
    }

    /// Mounts the npk root fs to target and returns the device used to mount (loopback or device mapper)
    pub(super) fn mount(
        &self,
        npk: &Npk,
        target: &Path,
        key: Option<&PublicKey>,
    ) -> impl Future<Output = Result<()>> {
        let dm = self.dm.clone();
        let lc = self.lc.clone();
        let key = key.cloned();
        let target = target.to_owned();
        let fd = npk.as_raw_fd();
        let fsimg_size = npk.fsimg_size();
        let fsimg_offset = npk.fsimg_offset();
        let container = npk.manifest().container();
        let verity_header = npk.verity_header().cloned();
        let selinux_context = npk.manifest().selinux.as_ref().map(|s| s.context.clone());
        let hashes = npk.hashes().cloned();
        let lo_timeout = self.lo_timeout;

        task::spawn_blocking(move || {
            let mount_info = Mount {
                container: &container,
                fd,
                fsimg_offset,
                fsimg_size,
                verity_header: verity_header.as_ref(),
                selinux_context: selinux_context.as_ref(),
                hashes: hashes.as_ref(),
                target: &target,
                key: key.as_ref(),
                lo_timeout,
            };
            debug!("Mounting {container}");
            mount(dm, lc, mount_info).map(drop)
        })
        .map(|r| match r {
            Ok(r) => r,
            Err(e) => panic!("task error: {e}"),
        })
    }

    /// Umount target
    pub(super) fn umount(target: &Path) -> impl Future<Output = Result<()>> {
        let target = target.to_owned();

        task::spawn_blocking(move || {
            debug!("Unmounting {}", target.display());
            nix::mount::umount(&target)?;

            debug!("Removing mountpoint {}", target.display());
            fs::remove_dir(&target)
                .with_context(|| format!("failed to remove {}", target.display()))?;

            Ok(())
        })
        .map(|r| match r {
            Ok(r) => r,
            Err(e) => panic!("Task error: {e}"),
        })
    }
}

fn mount(
    dm: Arc<devicemapper::DeviceMapper>,
    lc: Arc<Mutex<LoopControl>>,
    mount_info: Mount,
) -> Result<()> {
    let Mount {
        container,
        fd,
        fsimg_offset,
        fsimg_size,
        verity_header,
        selinux_context,
        hashes,
        target,
        key,
        lo_timeout,
    } = mount_info;
    if !target.exists() {
        debug!("Creating mount point {}", target.display());
        fs::create_dir_all(target)
            .with_context(|| format!("failed to create directory {}", target.display()))?;
    }

    let (loopdevice, loopdevice_path) = {
        let lc = lc.lock().expect("failed to lock loop control");
        losetup(container, &lc, fd, fsimg_offset, fsimg_size, lo_timeout)
            .context("losetup failed")?
    };

    let (device, dm_name) = if key.is_none() {
        // We're done. Use the loop device path e.g. /dev/loop4
        (loopdevice_path, None)
    } else {
        let name = format!("northstar-{}", nanoid::nanoid!());
        let device = match (&verity_header, hashes) {
            (Some(header), Some(hashes)) => {
                debug!("Using loop device {}", loopdevice_path.display());
                dmsetup(&dm, &loopdevice_path, header, &name, hashes)
                    .context("failed to setup dm device")?
            }
            _ => {
                warn!(
                    "Cannot mount {container} without verity information from a repository with key",
                );

                // The loopdevice has been attached before. Ensure that it is detached in order
                // to avoid leaking the loop device. If the detach failed something is really
                // broken and probably best is to propagate the error with a panic.
                warn!(
                    "Detaching {} because of failed dmsetup",
                    loopdevice_path.display()
                );
                loopdevice
                    .detach()
                    .expect("failed to detach loopback device");

                bail!("NPK lacks verity information")
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
    let data = if let Some(selinux_context) = selinux_context {
        if Path::new("/sys/fs/selinux/enforce").exists() {
            Some(format!("{}{}", "context=", selinux_context.as_str()))
        } else {
            warn!("Failed to determine SELinux status of host system. SELinux is disabled.");
            None
        }
    } else {
        None
    };
    let data = data.as_deref();
    let mount_result = nix::mount::mount(source, target, fstype, flags, data);

    if let Err(ref e) = mount_result {
        warn!("Failed to mount: {}", e);
    }

    // Set the device to auto-remove. If the above mount operation failed the verity device is removed.
    // If the deferred removal fail the runtime panics in order to avoid leaking the verity device.
    if let Some(ref dm_name) = dm_name {
        dm.delete_device_deferred(dm_name)?;
    }

    mount_result.map_err(Into::into)
}

fn losetup(
    container: &Container,
    lc: &LoopControl,
    fd: RawFd,
    offset: u64,
    size: u64,
    timeout: time::Duration,
) -> Result<(LoopDevice, PathBuf)> {
    let start = Instant::now();

    // Acquire a loop device and attach the backing file. This operation is racy because
    // getting the next free index and attaching is not atomic. Retry the operation in a
    // loop until successful or timeout.
    for n in 1..u64::MAX {
        let loop_device = match lc.next_free() {
            Ok(loop_device) => loop_device,
            Err(e) => match e.raw_os_error() {
                Some(EBUSY) | Some(EAGAIN) => continue,
                _ => return Err(e.into()),
            },
        };

        let path = loop_device
            .path()
            .ok_or_else(|| anyhow!("failed to get loop device path"))?;

        match loop_device
            .with()
            .offset(offset)
            .size_limit(size)
            .read_only(true)
            .autoclear(true)
            .attach_fd(fd)
        {
            Ok(_) => {
                debug!(
                    "Attached {container} to {} after {n} attempt(s)",
                    path.display(),
                );
                return Ok((loop_device, path));
            }
            Err(e) => match e.raw_os_error() {
                Some(EBUSY) | Some(EAGAIN) => {
                    if start.elapsed() > timeout {
                        bail!("failed to acquire loop device for {container} within {timeout:?}");
                    }
                }
                _ => return Err(e.into()),
            },
        }
    }

    unreachable!()
}

fn dmsetup(
    dm: &devicemapper::DeviceMapper,
    dev: &Path,
    verity: &VerityHeader,
    name: &str,
    hashes: &Hashes,
) -> Result<PathBuf> {
    let verity_hash = &hashes.fs_verity_hash;
    let data_size = hashes.fs_verity_offset;
    let hash_block_size = verity.hash_block_size as u64;
    let data_block_size = verity.data_block_size as u64;
    let salt = &verity.salt[..(verity.salt_size as usize)];
    let target = devicemapper::verity::DmVerityTargetBuilder::default()
        .data_device(dev, data_size, data_block_size)
        .hash_device(dev, hash_block_size)
        .root_digest(verity_hash)
        .salt(salt)
        .hash_algorithm(DmVerityHashAlgorithm::SHA256)
        .build()?;

    debug!("Creating verity device of {}", dev.display());
    let device = match dm.create_verity_device(name, target.as_slice()) {
        Ok(device) => device,
        Err(e) => {
            warn!("failed to setup {}", name);
            debug!("Trying to remove device {}", name);
            if let Err(e) = dm.delete_device_deferred(name) {
                warn!("failed to remove {} with {}", name, e);
            }
            return Err(e);
        }
    };

    Ok(device)
}
