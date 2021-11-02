use super::{key::PublicKey, repository::Npk};
use crate::{
    common::{name::Name, version::Version},
    npk::{dm_verity::VerityHeader, npk::Hashes},
};
use devicemapper::{DevId, DmError, DmName, DmUuid};
use floating_duration::TimeAsFloat;
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
        let lc = LoopControl::open().map_err(Error::LoopDevice)?;
        let dm = devicemapper::DM::new().map_err(Error::DeviceMapper)?;
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
                "Mounted {}:{} Mounting: {:.03}s",
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
            debug!("Removing device {}", dm_name);

            self.dm
                .device_remove(
                    &DevId::Name(DmName::new(dm_name).unwrap()),
                    devicemapper::DmOptions::default(),
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
    let dm_name = format!("northstar_{}_{}_{}", process::id(), name, version);

    // Acquire a loop device and attach the backing file. This operation is racy because
    // getting the next free index and attaching is not atomic. Retry the operation in a
    // loop until successful or timeout.
    let start = time::Instant::now();
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
        if start.elapsed() > time::Duration::from_secs(5) {
            return Err(Error::Timeout("Failed to acquire loop device".into()));
        }
    };

    let device = if !verity {
        // We're done. Use the loop device path e.g. /dev/loop4
        loop_device.path().unwrap()
    } else {
        match (&verity_header, hashes) {
            (Some(header), Some(hashes)) => {
                let (major, minor) = (loop_device.major().unwrap(), loop_device.minor().unwrap());
                let loop_device_id = format!("{}:{}", major, minor);

                debug!("Loop device id is {}", loop_device_id);

                let verity_device = dmsetup(
                    dm.clone(),
                    &loop_device_id,
                    header,
                    &dm_name,
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
                return Err(Error::Npk("Missing verity information in NPK"));
            }
        }
    };

    if !target.exists() {
        debug!("Creating mount point {}", target.display());
        std::fs::create_dir_all(&target).map_err(|e| {
            Error::Io(
                format!("Failed to create directory {}", target.display()),
                e,
            )
        })?;
    }

    // Finally mount
    debug!(
        "Mounting {} fs on {} to {}",
        FS_TYPE,
        device.display(),
        target.display(),
    );
    let flags = MountFlags::MS_RDONLY | MountFlags::MS_NOSUID;
    nix::mount::mount(
        Some(&device),
        target,
        Some(FS_TYPE),
        flags,
        Option::<&str>::None,
    )
    .map_err(Error::Os)?;

    // Set the device to auto-remove once unmounted
    let dm_name = if verity {
        debug!("Enabling deferred removal on device {}", dm_name);
        dm.device_remove(
            &DevId::Name(DmName::new(&dm_name).unwrap()),
            devicemapper::DmOptions::default().set_flags(devicemapper::DmFlags::DM_DEFERRED_REMOVE),
        )
        .map_err(Error::DeviceMapper)?;

        Some(dm_name)
    } else {
        None
    };

    Ok(MountInfo {
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
    debug!("Creating a read-only verity device {}", &name);
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

    let name = DmName::new(name).unwrap();
    let id = DevId::Name(name);

    let uuid = uuid::Uuid::new_v4().to_string();
    let uuid = DmUuid::new(&uuid).map_err(Error::DeviceMapper)?;

    let dm_device = dm
        .device_create(
            name,
            Some(uuid),
            devicemapper::DmOptions::default().set_flags(devicemapper::DmFlags::DM_READONLY),
        )
        .map_err(Error::DeviceMapper)?;
    let dm_dev = PathBuf::from(format!("{}{}", DEVICE_MAPPER_DEV, dm_device.device().minor));

    debug!("Created verity device {}", dm_dev.display());

    dm.table_load(
        &id,
        &table,
        devicemapper::DmOptions::default().set_flags(devicemapper::DmFlags::DM_READONLY),
    )
    .map_err(Error::DeviceMapper)?;

    debug!("Resuming device {}", dm_dev.display());
    dm.device_suspend(&id, devicemapper::DmOptions::default())
        .map_err(Error::DeviceMapper)?;

    debug!("Waiting for device {}", dm_dev.display());
    while !dm_dev.exists() {
        // Use a std::thread::sleep because this is run on a futures
        // executor and not a tokio runtime
        thread::sleep(time::Duration::from_millis(1));
    }

    let veritysetup_duration = start.elapsed();
    debug!(
        "Verity completed after {:.03}s",
        veritysetup_duration.as_fractional_secs()
    );

    Ok(dm_dev)
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
