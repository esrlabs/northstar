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

#[allow(unused)]
pub(super) mod device_mapper;
pub(super) mod loopdev;
pub(super) mod minijail;
pub(super) mod mount;
pub(super) mod verity;

use super::{
    error::Error as NorthError,
    linux::{
        self, device_mapper as dm,
        loopdev::{losetup, LoopControl},
        mount as linux_mount,
    },
};
use crate::runtime::linux::verity::veritysetup;
use ed25519_dalek::PublicKey;
use floating_duration::TimeAsFloat;
use log::{debug, info};
use npk::{
    archive::{ArchiveReader, Container},
    check_verity_config, get_fs_type, read_verity_header, VerityHeader,
};
use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    process,
};
use thiserror::Error;
use tokio::{fs, fs::metadata, stream::StreamExt, time};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Mount error")]
    Mount(#[from] mount::Error),
    #[error("Unshare error: {0}")]
    Unshare(String, #[source] nix::Error),
    #[error("Pipe error")]
    Pipe(#[from] nix::Error),
    #[error("Device mapper error: {0}")]
    DeviceMapper(device_mapper::Error),
    #[error("Loop device error: {0}")]
    LoopDevice(loopdev::Error),
    #[error("Inotify")]
    INotify(#[from] super::inotify::Error),
    #[error("File operation error: {0}")]
    FileOperation(String, #[source] io::Error),
}

pub async fn mount_all(
    run_dir: &Path,
    signing_keys: &HashMap<String, PublicKey>,
    device_mapper_dev: &str,
    device_mapper: &Path,
    loop_control: &Path,
    loop_dev: &str,
    dir: &Path,
) -> Result<Vec<Container>, NorthError> {
    info!("Installing containers from {}", dir.display());

    let npks = fs::read_dir(&dir)
        .await
        .map_err(|e| linux::Error::FileOperation(format!("Failed to read {}", dir.display()), e))?
        .filter_map(move |d| d.ok())
        .map(|d| d.path());

    let dm = dm::Dm::new(&device_mapper).map_err(linux::Error::DeviceMapper)?;
    let lc = LoopControl::open(loop_control, loop_dev)
        .await
        .map_err(linux::Error::LoopDevice)?;

    let mut npks = Box::pin(npks);

    let mut containers: Vec<Vec<Container>> = vec![];
    while let Some(npk) = npks.next().await {
        containers.push(
            mount_internal(&run_dir, &signing_keys, &device_mapper_dev, &dm, &lc, &npk).await?,
        );
    }
    Ok(containers.into_iter().flatten().collect())
}

pub async fn unpack_and_mount(
    run_dir: &Path,
    signing_keys: &HashMap<String, PublicKey>,
    device_mapper_dev: &str,
    device_mapper: &Path,
    loop_control: &Path,
    loop_dev: &str,
    npk: &Path,
) -> Result<Vec<Container>, NorthError> {
    debug!("Mounting {}", npk.display());

    let dm = dm::Dm::new(&device_mapper).map_err(linux::Error::DeviceMapper)?;
    let lc = LoopControl::open(loop_control, loop_dev)
        .await
        .map_err(linux::Error::LoopDevice)?;

    let mounted_containers =
        mount_internal(run_dir, signing_keys, device_mapper_dev, &dm, &lc, npk).await?;

    Ok(mounted_containers)
}

pub async fn umount_and_remove(container: &Container) -> Result<(), linux::Error> {
    debug!("Umounting {}", container.root.display());
    linux_mount::unmount(&container.root)
        .await
        .map_err(linux::Error::Mount)?;

    debug!("Waiting for dm device removal");
    super::inotify::wait_for_file_deleted(&container.dm_dev, std::time::Duration::from_secs(5))
        .await
        .map_err(Error::INotify)?;

    debug!("Removing mountpoint {}", container.root.display());
    // Root which is the container version
    fs::remove_dir(&container.root).await.map_err(|e| {
        linux::Error::FileOperation(format!("Failed to remove {}", container.root.display()), e)
    })?;
    // Container name
    fs::remove_dir(
        container
            .root
            .parent()
            .expect("Could not get parent dir of container!"),
    )
    .await
    .map_err(|e| {
        linux::Error::FileOperation(format!("Failed to remove {}", container.root.display()), e)
    })?;

    Ok(())
}

async fn mount_internal(
    run_dir: &Path,
    signing_keys: &HashMap<String, PublicKey>,
    device_mapper_dev: &str,
    dm: &dm::Dm,
    lc: &LoopControl,
    npk: &Path,
) -> Result<Vec<Container>, NorthError> {
    let start = time::Instant::now();

    if let Ok(meta) = metadata(&npk).await {
        debug!("Mounting NPK with size {}", meta.len());
    }
    let mut archive_reader =
        ArchiveReader::new(&npk, signing_keys).map_err(|e| NorthError::Npk(e.into()))?;

    let hashes = archive_reader
        .extract_hashes()
        .map_err(|e| NorthError::Npk(e.into()))?;

    let manifest = archive_reader
        .extract_manifest_from_archive()
        .map_err(|e| NorthError::Npk(e.into()))?;
    debug!("Loaded manifest of {}:{}", manifest.name, manifest.version);

    let (fs_offset, fs_size) = archive_reader
        .extract_fs_start_and_size()
        .map_err(|e| NorthError::Npk(e.into()))?;

    let mut fs = fs::File::open(&npk)
        .await
        .map_err(|error| linux::Error::FileOperation(format!("Failed to open {:?}", npk), error))?;

    let verity = read_verity_header(&mut fs, fs_offset, hashes.fs_verity_offset)
        .await
        .map_err(NorthError::Npk)?;

    check_verity_config(&verity).map_err(NorthError::Npk)?;

    let instances = manifest.instances.unwrap_or(1);

    let mut mounted_containers = vec![];
    for instance in 0..instances {
        let mut manifest = manifest.clone();
        if instances > 1 {
            manifest.name.push_str(&format!("-{:03}", instance));
        }
        let root = run_dir
            .join(&manifest.name)
            .join(&format!("{}", manifest.version));

        if !root.exists() {
            info!("Creating mountpoint {}", root.display());
            fs::create_dir_all(&root).await.map_err(|e| {
                linux::Error::FileOperation(format!("Failed to create mountpoint: {}", e), e)
            })?;
        }

        let name = format!(
            "north_{}_{}_{}",
            process::id(),
            manifest.name,
            manifest.version
        );

        let dm_dev = setup_and_mount(
            dm,
            lc,
            &verity,
            &name,
            device_mapper_dev,
            hashes.fs_verity_offset,
            &hashes.fs_verity_hash,
            &npk,
            &mut fs,
            fs_offset,
            fs_size,
            &root,
        )
        .await?;

        let container = Container {
            root,
            manifest,
            dm_dev,
        };

        let duration = start.elapsed();

        info!(
            "Installed {}:{} Mounting: {:.03}s",
            container.manifest.name,
            container.manifest.version,
            duration.as_fractional_secs(),
        );
        mounted_containers.push(container);
    }

    Ok(mounted_containers)
}

#[allow(clippy::too_many_arguments)]
async fn setup_and_mount(
    dm: &dm::Dm,
    lc: &LoopControl,
    verity: &VerityHeader,
    name: &str,
    dm_dev: &str,
    dm_device_size: u64,
    verity_hash: &str,
    fs_path: &Path,
    mut fs: &mut fs::File,
    fs_offset: u64,
    lo_size: u64,
    root: &Path,
) -> Result<PathBuf, linux::Error> {
    let fs_type = get_fs_type(&mut fs, fs_offset).await.map_err(|e| {
        linux::Error::FileOperation(format!("Failed get file-system-type {}", e), e)
    })?;

    let loop_device = losetup(lc, fs_path, fs, fs_offset, lo_size).await?;

    let loop_device_id = loop_device
        .dev_id()
        .await
        .map(|(major, minor)| format!("{}:{}", major, minor))
        .map_err(linux::Error::LoopDevice)?;

    let dm_dev = veritysetup(
        &dm,
        &dm_dev,
        &loop_device_id,
        &verity,
        name,
        verity_hash,
        dm_device_size,
    )
    .await?;

    linux_mount::mount_device(&dm_dev, root, fs_type).await?;

    dm.device_remove(
        &name.to_string(),
        &dm::DmOptions::new().set_flags(dm::DmFlags::DM_DEFERRED_REMOVE),
    )
    .await
    .map_err(linux::Error::DeviceMapper)?;

    Ok(dm_dev)
}
