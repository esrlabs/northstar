use crate::{
    common::container::Container,
    npk::{dm_verity::VerityHeader, manifest::selinux::Selinux, npk::Hashes},
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
use std::{
    os::unix::{io::AsRawFd, prelude::RawFd},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{task, time};

pub use nix::mount::MsFlags as MountFlags;

const FS_TYPE: &str = "squashfs";

pub(super) struct MountControl {
    /// Timeout for lo device setup
    lo_timeout: time::Duration,
    /// Device mapper handle
    dm: Arc<devicemapper::DeviceMapper>,
    /// Loop device control
    lc: Arc<loopdev::LoopControl>,
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
        let selinux = npk.manifest().selinux.clone();
        let hashes = npk.hashes().cloned();
        let lo_timeout = self.lo_timeout;

        task::spawn_blocking(move || {
            let start = time::Instant::now();

            debug!("Mounting {container}");
            mount(
                &container,
                dm,
                lc,
                fd,
                fsimg_offset,
                fsimg_size,
                verity_header,
                selinux,
                hashes,
                &target,
                key.is_some(),
                lo_timeout,
            )?;

            let duration = start.elapsed();
            debug!("Finished mount of {container} in {duration:?}");

            Ok(())
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
            let start = time::Instant::now();

            debug!("Unmounting {}", target.display());
            nix::mount::umount(&target)?;

            debug!("Removing mountpoint {}", target.display());
            std::fs::remove_dir(&target)
                .with_context(|| format!("failed to remove {}", target.display()))?;

            let duration = start.elapsed();
            debug!("Finished umount of {} in {duration:?}", target.display(),);

            Ok(())
        })
        .map(|r| match r {
            Ok(r) => r,
            Err(e) => panic!("Task error: {e}"),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn mount(
    container: &Container,
    dm: Arc<devicemapper::DeviceMapper>,
    lc: Arc<LoopControl>,
    fd: RawFd,
    fsimg_offset: u64,
    fsimg_size: u64,
    verity_header: Option<VerityHeader>,
    selinux: Option<Selinux>,
    hashes: Option<Hashes>,
    target: &Path,
    verity: bool,
    lo_timeout: time::Duration,
) -> Result<()> {
    if !target.exists() {
        debug!("Creating mount point {}", target.display());
        std::fs::create_dir_all(target)
            .with_context(|| format!("failed to create directory {}", target.display()))?;
    }

    // losetup
    let (loopdevice, loopdevice_path) =
        losetup(container, &lc, fd, fsimg_offset, fsimg_size, lo_timeout)?;

    let (device, dm_name) = if !verity {
        // We're done. Use the loop device path e.g. /dev/loop4
        (loopdevice_path, None)
    } else {
        let name = format!("northstar-{}", nanoid::nanoid!());
        let device = match (&verity_header, hashes) {
            (Some(header), Some(hashes)) => {
                debug!("Using loop device {}", loopdevice_path.display());
                dmsetup(
                    dm.clone(),
                    &loopdevice_path,
                    header,
                    &name,
                    &hashes.fs_verity_hash,
                    hashes.fs_verity_offset,
                )?
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
    let data = if let Some(selinux) = selinux {
        if Path::new("/sys/fs/selinux/enforce").exists() {
            Some(format!("{}{}", "context=", selinux.context.as_str()))
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
    let start = time::Instant::now();

    // Acquire a loop device and attach the backing file. This operation is racy because
    // getting the next free index and attaching is not atomic. Retry the operation in a
    // loop until successful or timeout.
    for n in 1..u64::MAX {
        let loop_device = lc.next_free()?;
        if loop_device
            .with()
            .offset(offset)
            .size_limit(size)
            .read_only(true)
            .autoclear(true)
            .attach_fd(fd)
            .is_ok()
        {
            let path = loop_device
                .path()
                .ok_or_else(|| anyhow!("failed to get loop device path"))?;
            debug!(
                "Attached {container} to {} after {n} attempt(s) in {:?}",
                path.display(),
                start.elapsed()
            );
            return Ok((loop_device, path));
        }

        if start.elapsed() > timeout {
            bail!("failed to acquire loop device for {container} within {timeout:?}");
        }
    }

    unreachable!()
}

fn dmsetup(
    dm: Arc<devicemapper::DeviceMapper>,
    dev: &Path,
    verity: &VerityHeader,
    name: &str,
    verity_hash: &str,
    data_size: u64,
) -> Result<PathBuf> {
    let start = time::Instant::now();

    let salt = &verity.salt[..(verity.salt_size as usize)];
    let target = devicemapper::verity::DmVerityTargetBuilder::default()
        .data_device(dev, data_size, verity.data_block_size as u64)
        .hash_device(dev, verity.hash_block_size as u64)
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

    let duration = start.elapsed().as_secs_f32();
    debug!(
        "Finishing verity device setup of {} after {:.03}s",
        device.display(),
        duration,
    );

    Ok(device)
}
