use super::{key::PublicKey, repository::Npk};
use crate::{
    common::{name::Name, version::Version},
    npk::{dm_verity::VerityHeader, npk::Hashes},
    util::TimeAsFloat,
};
use devicemapper::{DevId, DmError, DmName, DmOptions, DmUuid};
use futures::{Future, StreamExt};
use inotify::WatchMask;
use log::{debug, info, warn};
use loopdev::LoopControl;
pub use nix::mount::MsFlags as MountFlags;
use std::{
    io,
    os::unix::{io::AsRawFd, prelude::RawFd},
    path::{Path, PathBuf},
    process,
    str::Utf8Error,
    sync::Arc,
    thread,
};
use thiserror::Error;
use tokio::{fs, time};

const FS_TYPE: &str = "squashfs";

#[cfg(not(target_os = "android"))]
const DEVICE_MAPPER_DEV: &str = "/dev/dm-";
#[cfg(target_os = "android")]
const DEVICE_MAPPER_DEV: &str = "/dev/block/dm-";

/// Maximum duration to wait for a device mapper device to be removed by the
/// kernel after umount.
const DM_DEVICE_TIMEOUT: time::Duration = time::Duration::from_secs(10);
/// Loop device acquire timeout
const LOOP_DEVICE_TIMEOUT: time::Duration = time::Duration::from_secs(10);

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}: {1:?}")]
    Io(String, io::Error),
    #[error("Os error: {0}")]
    Os(nix::Error),
    #[error("Device mapper error: {0:?}")]
    DeviceMapper(DmError),
    #[error("Loop device error: {0:?}")]
    LoopDevice(io::Error),
    #[error("NPK error: {0:?}")]
    Npk(&'static str),
    #[error("UTF-8 conversion error: {0:?}")]
    Utf8Conversion(Utf8Error),
    #[error("Timeout error {0}")]
    Timeout(String),
}

#[derive(Debug)]
pub(super) struct MountInfo {
    pub device: PathBuf,
    pub target: PathBuf,
    pub dm_name: Option<String>,
}

pub(super) struct MountControl {
    dm: Arc<devicemapper::DM>,
    lc: Arc<loopdev::LoopControl>,
}

impl std::fmt::Debug for MountControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountControl").finish()
    }
}

impl MountControl {
    pub(super) async fn new() -> Result<MountControl, Error> {
        debug!("Opening loop control");
        let lc = LoopControl::open().map_err(Error::LoopDevice)?;
        debug!("Opening device mapper control");
        let dm = devicemapper::DM::new().map_err(Error::DeviceMapper)?;

        let dm_version = dm
            .version()
            .map_err(Error::DeviceMapper)
            .map(Version::from)?;
        debug!("Device mapper version is {}", dm_version);

        Ok(MountControl {
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
    ) -> impl Future<Output = Result<MountInfo, Error>> {
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
        let hashes = npk.hashes().cloned();

        async move {
            let start = time::Instant::now();

            debug!("Mounting {}:{}", name, version);
            let device = mount(
                dm,
                lc,
                fd,
                fsimg_offset,
                fsimg_size,
                &name,
                &version,
                verity_header,
                hashes,
                &target,
                key.is_some(),
            )
            .await?;

            let duration = start.elapsed();
            info!(
                "Finishing mount of {}:{} after {:.03}s",
                name,
                version,
                duration.as_fractional_secs(),
            );

            Ok(device)
        }
    }

    pub(super) async fn umount(&self, mount_info: &MountInfo) -> Result<(), Error> {
        debug!("Unmounting {}", mount_info.target.display());

        if let Some(dm_name) = mount_info.dm_name.as_ref() {
            debug!("Removing verity device {}", dm_name);

            self.dm
                .device_remove(
                    &DevId::Name(DmName::new(dm_name).unwrap()),
                    DmOptions::default(),
                )
                .ok();

            nix::mount::umount(&mount_info.target).map_err(Error::Os)?;

            debug!("Waiting for dm device {}", mount_info.device.display());
            wait_file_deleted(&mount_info.device, time::Duration::from_secs(5)).await?;
        } else {
            nix::mount::umount(&mount_info.target).map_err(Error::Os)?;
        }

        debug!("Removing mountpoint {}", mount_info.target.display());

        fs::remove_dir(&mount_info.target).await.map_err(|e| {
            Error::Io(
                format!("Failed to remove {}", mount_info.target.display()),
                e,
            )
        })?;

        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn mount(
    dm: Arc<devicemapper::DM>,
    lc: Arc<LoopControl>,
    fd: RawFd,
    fsimg_offset: u64,
    fsimg_size: u64,
    name: &Name,
    version: &Version,
    verity_header: Option<VerityHeader>,
    hashes: Option<Hashes>,
    target: &Path,
    verity: bool,
) -> Result<MountInfo, Error> {
    // Acquire a loop device and attach the backing file. This operation is racy because
    // getting the next free index and attaching is not atomic. Retry the operation in a
    // loop until successful or timeout.
    let start = time::Instant::now();

    if !target.exists() {
        debug!("Creating mount point {}", target.display());
        std::fs::create_dir_all(&target).map_err(|e| {
            Error::Io(
                format!("Failed to create directory {}", target.display()),
                e,
            )
        })?;
    }

    let loop_device = loop {
        let loop_device = lc.next_free().map_err(Error::LoopDevice)?;
        if loop_device
            .with()
            .offset(fsimg_offset)
            .size_limit(fsimg_size)
            .read_only(true)
            .autoclear(true)
            .attach_fd(fd)
            .map_err(Error::LoopDevice)
            .is_ok()
        {
            break loop_device;
        }
        if start.elapsed() > LOOP_DEVICE_TIMEOUT {
            return Err(Error::Timeout("Failed to acquire loop device".into()));
        }
    };

    let (device, dm_name) = if !verity {
        // We're done. Use the loop device path e.g. /dev/loop4
        (loop_device.path().unwrap(), None)
    } else {
        let name = format!("northstar_{}_{}_{}", process::id(), name, version);
        let device = match (&verity_header, hashes) {
            (Some(header), Some(hashes)) => {
                let (major, minor) = (loop_device.major().unwrap(), loop_device.minor().unwrap());
                let loop_device_id = format!("{}:{}", major, minor);

                debug!("Using loop device id {}", loop_device_id);

                let verity_device = dmsetup(
                    dm.clone(),
                    &loop_device_id,
                    header,
                    &name,
                    hashes.fs_verity_hash.as_str(),
                    hashes.fs_verity_offset,
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
                warn!(
                    "Detaching {} because of failed dmsetup",
                    loop_device.path().unwrap().display()
                );
                loop_device
                    .detach()
                    .map_err(Error::LoopDevice)
                    .expect("Failed to detach loopbach device");

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
    let data = Option::<&str>::None;
    let mount_result = nix::mount::mount(source, target, fstype, flags, data).map_err(Error::Os);

    if let Err(ref e) = mount_result {
        warn!("Failed to mount: {}", e);
    }

    // Set the device to auto-remove. If the above mount operation failed the verity device is removed.
    // If the defered removal fail the runtime panics in order to avoid leaking the verity device.
    if let Some(ref dm_name) = dm_name {
        debug!("Enabling deferred removal of device {}", dm_name);
        dm.device_remove(
            &DevId::Name(DmName::new(&dm_name).unwrap()),
            DmOptions::default().set_flags(devicemapper::DmFlags::DM_DEFERRED_REMOVE),
        )
        .expect("Failed to enable deferred removal");
    }

    // Return the mount error of the happy result
    mount_result.map(|_| MountInfo {
        device,
        target: target.to_owned(),
        dm_name,
    })
}

fn dmsetup(
    dm: Arc<devicemapper::DM>,
    dev: &str,
    verity: &VerityHeader,
    name: &str,
    verity_hash: &str,
    size: u64,
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
    let name = DmName::new(name).unwrap();
    let id = DevId::Name(name);
    let uuid_str = uuid::Uuid::new_v4().to_string();
    let uuid = DmUuid::new(&uuid_str).unwrap();
    let uuid_display = &uuid_str[..8];

    debug!("Creating verity device {} ({}...)", name, uuid_display);
    let dm_device = dm
        .device_create(
            name,
            Some(uuid),
            DmOptions::default().set_flags(devicemapper::DmFlags::DM_READONLY),
        )
        .map_err(Error::DeviceMapper)?;

    let load = || {
        dm.table_load(
            &id,
            &table,
            DmOptions::default().set_flags(devicemapper::DmFlags::DM_READONLY),
        )
        .map_err(Error::DeviceMapper)?;

        let device = PathBuf::from(format!("{}{}", DEVICE_MAPPER_DEV, dm_device.device().minor));

        debug!(
            "Resuming verity device {} ({}...)",
            device.display(),
            uuid_display
        );
        dm.device_suspend(&id, DmOptions::default())
            .map_err(Error::DeviceMapper)?;

        debug!(
            "Waiting for verity device {} ({}...)",
            device.display(),
            uuid_display
        );
        while !device.exists() {
            // Use a std::thread::sleep because this is run on a futures
            // executor and not a tokio runtime
            thread::sleep(time::Duration::from_millis(1));

            if start.elapsed() > DM_DEVICE_TIMEOUT {
                return Err(Error::Timeout(format!(
                    "Timeout while waiting for verity device {} ({}...)",
                    device.display(),
                    uuid_display
                )));
            }
        }
        Ok(device)
    };

    let device = match load() {
        Ok(device) => device,
        Err(e) => {
            warn!("Failed to setup {} ({}...)", name, uuid_display);
            debug!("Trying to remove device {} ({}...)", name, uuid_display);
            if let Err(e) = dm.device_remove(&id, DmOptions::default()) {
                warn!("Failed to remove {} ({}...) with {}", name, uuid_display, e);
            }
            return Err(e);
        }
    };

    let duration = start.elapsed().as_fractional_secs();
    debug!(
        "Finishing verity device setup of {} ({}...) after {:.03}s",
        device.display(),
        uuid_display,
        duration,
    );

    Ok(device)
}

async fn wait_file_deleted(path: &Path, timeout: time::Duration) -> Result<(), Error> {
    let mut inotify =
        inotify::Inotify::init().map_err(|e| Error::Io("Initialize inotify".into(), e))?;

    let path = path.to_owned();
    match inotify.add_watch(&path, WatchMask::DELETE) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(Error::Io(
                format!("Inotify watch path: {}", path.display()),
                e,
            ));
        }
    };

    let buffer = [0u8; 1024];
    let mut stream = inotify
        .event_stream(buffer)
        .map_err(|e| Error::Io("Inotify event stream".into(), e))?;

    match time::timeout(timeout, stream.next())
        .await
        .map_err(|_| Error::Timeout(format!("Inotify timeout deletion of {}", path.display())))?
    {
        Some(Ok(_)) => Ok(()),
        Some(Err(e)) => Err(Error::Io("Inotify stream error".into(), e)),
        None => unreachable!("Inotify closed"),
    }
}

#[cfg(test)]
mod tests {
    use super::wait_file_deleted;
    use std::{path::Path, time::Duration};
    use tokio::{fs, task};

    #[tokio::test]
    async fn wait_for_non_existing_file() {
        assert!(
            wait_file_deleted(Path::new("non_existing_file"), Duration::from_millis(0))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn wait_for_file_deleted() {
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("foo");
        for _ in 0..1000 {
            let _ = fs::File::create(&path).await.unwrap();
            task::spawn(fs::remove_file(path.clone()));
            wait_file_deleted(&path, Duration::from_secs(5))
                .await
                .unwrap();
            assert!(!path.exists());
        }
    }
}
