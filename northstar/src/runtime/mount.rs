use super::{key::PublicKey, state::Npk};
use crate::npk::dm_verity::VerityHeader;
use devicemapper::{DevId, DmError, DmName, DmUuid};
use floating_duration::TimeAsFloat;
use futures::Future;
use log::{debug, info, warn};
use loopdev::LoopControl;
pub use nix::mount::MsFlags as MountFlags;
use std::{
    io,
    os::unix::io::AsRawFd,
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
    device: PathBuf,
    target: PathBuf,
    dm_name: Option<String>,
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
        npk: Arc<Npk>,
        target: &Path,
        key: Option<&PublicKey>,
    ) -> impl Future<Output = Result<MountInfo, Error>> {
        let key = key.copied();
        let dm = self.dm.clone();
        let lc = self.lc.clone();
        let target = target.to_owned();

        async move {
            let start = time::Instant::now();

            debug!(
                "Mounting {}:{}",
                npk.manifest().name,
                npk.manifest().version
            );
            let device = mount(dm, lc, &npk, &target, key.is_some()).await?;
            let duration = start.elapsed();
            info!(
                "Mounted {}:{} Mounting: {:.03}s",
                npk.manifest().name,
                npk.manifest().version,
                duration.as_fractional_secs(),
            );

            Ok(device)
        }
    }

    pub(super) async fn umount(&self, mount_info: &MountInfo) -> Result<(), Error> {
        nix::mount::umount(&mount_info.target).map_err(Error::Os)?;

        if let Some(dm_name) = mount_info.dm_name.as_ref() {
            debug!("Removing device {}", dm_name);
            // Remove the device. The defered removal may have kicked in in between
            // and the `device_remove` call returns an error in such a case. Ignore
            // any error.
            self.dm
                .device_remove(
                    &DevId::Name(DmName::new(dm_name).unwrap()),
                    devicemapper::DmOptions::default(),
                )
                .ok();

            debug!("Waiting for dm device {}", mount_info.device.display());
            wait_for_file_deleted(&mount_info.device, std::time::Duration::from_secs(5)).await?;
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

async fn mount(
    dm: Arc<devicemapper::DM>,
    lc: Arc<LoopControl>,
    npk: &Arc<Npk>,
    target: &Path,
    verity: bool,
) -> Result<MountInfo, Error> {
    let verity_header = npk.verity_header().to_owned();
    let fsimg_offset = npk.fsimg_offset();
    let fsimg_size = npk.fsimg_size();
    let manifest = npk.manifest();
    let dm_name = format!(
        "northstar_{}_{}_{}",
        process::id(),
        manifest.name,
        manifest.version
    );

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
            .attach_fd(npk.as_raw_fd())
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
        match (&verity_header, &npk.hashes()) {
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
                    manifest.name, manifest.version
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
