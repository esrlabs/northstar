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
    config::Config,
    device_mapper as dm, device_mapper,
    loopdev::{losetup, LoopControl},
    state::{Container, Repository},
};
use bitflags::_core::str::Utf8Error;
use floating_duration::TimeAsFloat;
use log::{debug, info};
pub use nix::mount::MsFlags as MountFlags;
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
use npk::{
    dm_verity::VerityHeader,
    manifest::Manifest,
    npk::{Error::MalformedManifest, Npk},
};
use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
    process,
};
use thiserror::Error;
use tokio::{fs, fs::metadata, task, time};

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
    #[error("UTF-8 conversion error: {0:?}")]
    Utf8Conversion(Utf8Error),
    #[error("Inotify timeout error {0}")]
    Timeout(String),
    #[error("Task join error: {0}")]
    JoinError(tokio::task::JoinError),
    #[error("Os error: {0:?}")]
    Os(nix::Error),
    #[error("Repository error: {0:?}")]
    MissingKey(String),
}

pub(super) async fn mount_npk_repository(
    config: &Config,
    repo: &Repository,
) -> Result<Vec<Container>, Error> {
    info!("Mounting NPKs from {}", repo.dir.display());
    let mut dir = fs::read_dir(&repo.dir)
        .await
        .map_err(|e| Error::Io("Failed to read repository".to_string(), e))?;
    let mut containers = Vec::new();
    while let Ok(Some(entry)) = dir.next_entry().await {
        containers.push(mount_npk(&config, &entry.path(), repo).await?);
    }

    Ok(containers)
}

pub(super) async fn mount_npk(
    config: &Config,
    npk: &Path,
    repo: &Repository,
) -> Result<Container, Error> {
    debug!("Mounting {}", npk.display());
    let use_verity = repo.key.is_some();

    let start = time::Instant::now();

    if let Ok(meta) = metadata(&npk).await {
        debug!("Mounting NPK with size {}", meta.len());
    }

    let (manifest, npk_version) = tokio::task::block_in_place(|| {
        let file = std::fs::File::open(&npk)
            .map_err(|e| Error::Io(format!("Failed to open NPK at {}", npk.display()), e))?;
        let mut npk_archive = Npk::new(file).map_err(Error::Npk)?;

        // verify signature
        if let Some(pub_key) = repo.key {
            npk_archive.verify(&pub_key).map_err(Error::Npk)?;
        } else {
            return Err(Error::MissingKey(
                "No public key in repository to verify NPK signature".to_string(),
            ));
        }

        let npk_version = npk_archive.version().map_err(Error::Npk)?;
        Ok((npk_archive.manifest().map_err(Error::Npk)?, npk_version))
    })?;

    if npk_version != Manifest::VERSION {
        return Err(Error::Npk(MalformedManifest(format!(
            "Invalid NPK version (detected: {}, supported: {})",
            npk_version.to_string(),
            &Manifest::VERSION
        ))));
    }
    debug!("Loaded manifest of {}:{}", manifest.name, manifest.version);

    let root = config
        .run_dir
        .join(&manifest.name)
        .join(&format!("{}", manifest.version));

    if !root.exists() {
        info!("Creating mountpoint {}", root.display());
        fs::create_dir_all(&root)
            .await
            .map_err(|e| Error::Io(format!("Failed to create mountpoint: {}", e), e))?;
    }

    let name = format!(
        "north_{}_{}_{}",
        process::id(),
        manifest.name,
        manifest.version
    );

    let device = setup_and_mount(&config, &name, &npk, &root, use_verity).await?;

    let container = Container {
        root,
        manifest: manifest.clone(),
        device,
        repository: repo.id.to_string(),
    };

    let duration = start.elapsed();

    info!(
        "Installed {}:{} Mounting: {:.03}s",
        container.manifest.name,
        container.manifest.version,
        duration.as_fractional_secs(),
    );

    Ok(container)
}

pub async fn umount_npk(container: &Container, wait_for_dm: bool) -> Result<(), Error> {
    unmount(&container.root).await?;

    if wait_for_dm {
        debug!("Waiting for dm device removal");
        wait_for_file_deleted(&container.device, std::time::Duration::from_secs(5)).await?;
    }

    debug!("Removing mountpoint {}", container.root.display());
    // Root which is the container version
    fs::remove_dir(&container.root)
        .await
        .map_err(|e| Error::Io(format!("Failed to remove {}", container.root.display()), e))?;
    // Container name
    fs::remove_dir(
        container
            .root
            .parent()
            .expect("Failed to get parent dir of container!"),
    )
    .await
    .map_err(|e| Error::Io(format!("Failed to remove {}", container.root.display()), e))?;

    Ok(())
}

pub async fn verity_setup(
    config: &Config,
    dev: &str,
    verity: &VerityHeader,
    name: &str,
    verity_hash: &str,
    size: u64,
) -> Result<PathBuf, Error> {
    debug!("Creating a read-only verity device (name: {})", &name);
    let start = time::Instant::now();

    let dm = dm::Dm::new(&config.devices.device_mapper).map_err(Error::DeviceMapper)?;
    let dm_device = dm
        .device_create(
            &name,
            &dm::DmOptions::new().set_flags(dm::DmFlags::DM_READONLY),
        )
        .await
        .map_err(Error::DeviceMapper)?;

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

    let dm_dev = PathBuf::from(format!(
        "{}{}",
        config.devices.device_mapper_dev,
        dm_device.id() & 0xFF
    ));

    debug!("Verity-device used: {}", dm_dev.to_string_lossy());
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

#[allow(clippy::too_many_arguments)]
async fn setup_and_mount(
    config: &Config,
    name: &str,
    npk: &Path,
    root: &Path,
    use_verity: bool,
) -> Result<PathBuf, Error> {
    // open NPK synchronously
    let (verity, hashes, fsimg_offset, fsimg_size) = tokio::task::block_in_place(|| {
        let file = File::open(npk)
            .map_err(|e| npk::npk::Error::Io(format!("Failed to open NPK: {}", e)))?;
        let mut npk = Npk::new(file)?;
        Ok((
            npk.verity_header()?,
            npk.hashes()?,
            npk.fsimg_offset()?,
            npk.fsimg_size()?,
        ))
    })
    .map_err(Error::Npk)?;

    let mut npk_file = fs::File::open(npk)
        .await
        .map_err(|e| Error::Io("Failed to open NPK".to_string(), e))?;
    let lc = LoopControl::open(&config.devices.loop_control, &config.devices.loop_dev)
        .await
        .map_err(Error::LoopDevice)?;
    let loop_device = losetup(&lc, &mut npk_file, fsimg_offset, fsimg_size)
        .await
        .map_err(Error::LoopDevice)?;
    let loop_device_id = loop_device
        .dev_id()
        .await
        .map(|(major, minor)| format!("{}:{}", major, minor))
        .map_err(Error::LoopDevice)?;

    if !use_verity {
        let device = loop_device.path().await.unwrap();
        mount(&device, root, &FS_TYPE, MountFlags::MS_RDONLY, None).await?;
        Ok(device)
    } else {
        let dm = dm::Dm::new(&config.devices.device_mapper).map_err(Error::DeviceMapper)?;

        let dm_dev = verity_setup(
            &config,
            &loop_device_id,
            &verity,
            name,
            hashes.fs_verity_hash.as_str(),
            hashes.fs_verity_offset,
        )
        .await?;

        mount(&dm_dev, root, &FS_TYPE, MountFlags::MS_RDONLY, None).await?;

        dm.device_remove(
            &name.to_string(),
            &device_mapper::DmOptions::new().set_flags(device_mapper::DmFlags::DM_DEFERRED_REMOVE),
        )
        .await
        .map_err(Error::DeviceMapper)?;

        Ok(dm_dev)
    }
}

async fn unmount(target: &Path) -> Result<(), Error> {
    debug!("Unmounting {}", target.display(),);
    task::block_in_place(|| nix::mount::umount(target).map_err(Error::Os))
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
        "Mount {} fs on {} to {}",
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

#[allow(dead_code)]
async fn wait_for_file_deleted(path: &Path, timeout: time::Duration) -> Result<(), Error> {
    let notify_path = path.to_owned();
    let file_removed = task::spawn_blocking(move || {
        let inotify = Inotify::init(InitFlags::IN_CLOEXEC).map_err(Error::Os)?;
        inotify
            .add_watch(&notify_path, AddWatchFlags::IN_DELETE_SELF)
            .map_err(Error::Os)?;

        loop {
            if !notify_path.exists() {
                break;
            }
            inotify.read_events().map_err(Error::Os)?;
        }
        Result::<(), Error>::Ok(())
    });

    time::timeout(timeout, file_removed)
        .await
        .map_err(|_| Error::Timeout(format!("Inotify error on {}", &path.display())))
        .and_then(|r| r.map_err(Error::JoinError))
        .and_then(|r| r)
}
