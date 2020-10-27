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
    super::{
        linux::{
            device_mapper as dm,
            loopdev::{LoopControl, LoopDevice},
            mount as linux_mount,
        },
        state::State,
    },
    Container,
};
use crate::{
    manifest::{Mount, Name, Version},
    runtime::npk::{ArchiveReader, InstallFailure},
};
use async_std::{
    fs,
    fs::metadata,
    io,
    path::{Path, PathBuf},
    prelude::*,
    task,
};
use floating_duration::TimeAsFloat;
use fmt::Debug;
use futures::stream::StreamExt;
use log::*;
use std::{
    fmt::{self},
    process, time,
};

const SUPPORTED_VERITY_VERSION: u32 = 1;

struct VerityHeader {
    pub header: Vec<u8>,
    pub version: u32,
    pub algorithm: String,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_blocks: u64,
    pub salt: String,
}

pub async fn install_all(state: &mut State, dir: &Path) -> Result<(), InstallFailure> {
    info!("Installing containers from {}", dir.display());

    let npks = fs::read_dir(&dir)
        .await
        .map_err(|e| InstallFailure::FileIoProblem {
            context: format!("Failed to read {}", dir.display()),
            error: e,
        })?
        .filter_map(move |d| async move { d.ok() })
        .map(|d| d.path());

    let dm = state.config.devices.device_mapper.clone();
    let dm = dm::Dm::new(&dm).map_err(InstallFailure::DeviceMapperProblem)?;
    let lc: PathBuf = state.config.devices.loop_control.clone().into();
    let lc = LoopControl::open(&lc, &state.config.devices.loop_dev)
        .await
        .map_err(InstallFailure::LoopDeviceError)?;

    let mut npks = Box::pin(npks);
    while let Some(npk) = npks.next().await {
        install_internal(state, &dm, &lc, &npk).await?;
    }
    Ok(())
}

#[allow(dead_code)]
pub async fn install(
    state: &mut State,
    npk: &Path,
) -> std::result::Result<(Name, Version), InstallFailure> {
    debug!("Installing {}", npk.display());

    let dm = &state.config.devices.device_mapper.clone();
    let dm = dm::Dm::new(&dm).map_err(InstallFailure::DeviceMapperProblem)?;

    let lc: PathBuf = state.config.devices.loop_control.clone().into();
    let lc = LoopControl::open(&lc, &state.config.devices.loop_dev)
        .await
        .map_err(InstallFailure::LoopDeviceError)?;

    let (name, version) = install_internal(state, &dm, &lc, npk).await?;

    Ok((name, version))
}

#[allow(dead_code)]
pub async fn uninstall(container: &Container) -> Result<(), InstallFailure> {
    debug!("Unmounting {}", container.root.display());
    linux_mount::unmount(&container.root).await?;
    debug!("Removing {}", container.root.display());
    fs::remove_dir_all(&container.root)
        .await
        .map_err(|e| InstallFailure::FileIoProblem {
            context: format!("Failed to remove {}", container.root.display()),
            error: e,
        })?;

    crate::runtime::linux::inotify::wait_for_file_deleted(
        container.dm_dev.as_path().into(),
        std::time::Duration::from_secs(3),
    )
    .await?;
    Ok(())
}

async fn install_internal(
    state: &mut State,
    dm: &dm::Dm,
    lc: &LoopControl,
    npk: &Path,
) -> std::result::Result<(Name, Version), InstallFailure> {
    let start = time::Instant::now();
    if let Some(npk_name) = npk.file_name() {
        info!(
            "Installing {}, loading npk file",
            npk_name.to_string_lossy()
        );
    }

    if let Ok(md) = metadata(&npk).await {
        debug!("Installing an NPK with size: {}", md.len());
    }
    let p: &std::path::Path = npk.into();
    let mut archive_reader = ArchiveReader::new(&p, &state.signing_keys)?;

    let hashes = archive_reader.extract_hashes()?;

    let manifest = archive_reader.extract_manifest_from_archive()?;
    debug!("Manifest loaded for \"{}\"", manifest.name);

    let resources: Vec<String> = manifest
        .mounts
        .iter()
        .filter_map(|m| match m {
            Mount::Resource { name, version, .. } => Some(format!("{} ({})", name, version)),
            _ => None,
        })
        .collect();

    if !resources.is_empty() {
        debug!("Referencing {} resources:", resources.len());
        for res in resources {
            debug!("- {}", res);
        }
    }

    let (fs_offset, fs_size) = archive_reader.extract_fs_start_and_size()?;

    let mut fs =
        async_std::fs::File::open(&npk)
            .await
            .map_err(|e| InstallFailure::FileIoProblem {
                context: format!("Failed to open {:?} ({})", npk, e),
                error: e,
            })?;

    let verity = read_verity_header(&mut fs, fs_offset, hashes.fs_verity_offset)
        .await
        .map_err(|e| InstallFailure::VerityProblem(format!("Failed read verity header {}", e)))?;

    check_verity_config(&verity)?;

    let instances = manifest.instances.unwrap_or(1);

    for instance in 0..instances {
        let mut manifest = manifest.clone();
        if instances > 1 {
            manifest.name.push_str(&format!("-{:03}", instance));
        }
        let root = state
            .config
            .directories
            .run_dir
            .join(&manifest.name)
            .join(&format!("{}", manifest.version));
        let root: PathBuf = root.into();

        if !root.exists().await {
            info!("Creating mountpoint {}", root.display());
            fs::create_dir_all(&root)
                .await
                .map_err(|e| InstallFailure::FileIoProblem {
                    context: format!("Failed to create mountpoint: {}", e),
                    error: e,
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
            &state.config.devices.device_mapper_dev,
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

        state.add(container)?;
    }

    Ok((manifest.name, manifest.version))
}

fn check_verity_config(verity: &VerityHeader) -> Result<(), InstallFailure> {
    if &verity.header != b"verity" {
        return Err(InstallFailure::NoVerityHeader);
    }
    if verity.version != SUPPORTED_VERITY_VERSION {
        return Err(InstallFailure::UnexpectedVerityVersion(verity.version));
    }
    if verity.algorithm != "sha256" {
        return Err(InstallFailure::UnexpectedVerityAlgorithm(
            verity.algorithm.clone(),
        ));
    }
    Ok(())
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
) -> std::result::Result<PathBuf, InstallFailure> {
    let fs_type =
        get_fs_type(&mut fs, fs_offset)
            .await
            .map_err(|e| InstallFailure::FileIoProblem {
                context: format!("Failed get file-system-type {}", e),
                error: e,
            })?;

    let loop_device = losetup(lc, fs_path, fs, fs_offset, lo_size).await?;

    let loop_device_id = loop_device
        .dev_id()
        .await
        .map(|(major, minor)| format!("{}:{}", major, minor))
        .map_err(InstallFailure::LoopDeviceError)?;

    let dm_dev = veritysetup(
        &dm,
        &dm_dev,
        &loop_device_id,
        &verity,
        name,
        verity_hash,
        dm_device_size,
    )
    .await
    .map_err(|e| InstallFailure::VerityProblem(format!("Failed to find file-system {}", e)))?;

    mount(dm_dev.as_path(), root, fs_type).await?;

    dm.device_remove(
        &name.to_string(),
        &dm::DmOptions::new().set_flags(dm::DmFlags::DM_DEFERRED_REMOVE),
    )
    .await
    .map_err(InstallFailure::DeviceMapperProblem)?;

    Ok(dm_dev)
}

async fn get_fs_type(fs: &mut fs::File, fs_offset: u64) -> Result<&'static str, io::Error> {
    let mut fstype = [0u8; 4];
    fs.seek(io::SeekFrom::Start(fs_offset)).await?;
    fs.read_exact(&mut fstype).await?;

    Ok(if &fstype == b"hsqs" {
        debug!("Detected SquashFS file system");
        "squashfs"
    } else {
        debug!("Defaulting to ext filesystem type");
        "ext4"
    })
}

async fn read_verity_header(
    fs: &mut fs::File,
    fs_offset: u64,
    verity_offset: u64,
) -> Result<VerityHeader, InstallFailure> {
    let mut header = [0u8; 512];
    fs.seek(std::io::SeekFrom::Start(fs_offset + verity_offset))
        .await
        .map_err(|e| {
            InstallFailure::VerityProblem(format!("Could not seek to verity header: {}", e))
        })?;
    fs.read_exact(&mut header).await.map_err(|e| {
        InstallFailure::VerityProblem(format!("Could not read verity header: {}", e))
    })?;
    #[allow(clippy::too_many_arguments)]
    let s = structure::structure!("=6s2xII16s6s26xIIQH6x256s168x"); // "a8 L L a16 A32 L L Q S x6 a256"
    let (
        header,
        version,
        _hash_type,
        _uuid,
        algorithm,
        data_block_size,
        hash_block_size,
        data_blocks,
        salt_size,
        salt,
    ) = s.unpack(header.to_vec()).map_err(|e| {
        InstallFailure::VerityProblem(format!("Failed to decode verity block: {}", e))
    })?;

    Ok(VerityHeader {
        header,
        version,
        algorithm: std::str::from_utf8(&algorithm)
            .map_err(|e| {
                InstallFailure::VerityProblem(format!("Invalid algorithm in verity block: {}", e))
            })?
            .to_string(),
        data_block_size,
        hash_block_size,
        data_blocks,
        salt: hex::encode(&salt[..(salt_size as usize)]),
    })
}

async fn losetup(
    lc: &LoopControl,
    fs_path: &Path,
    fs: &mut fs::File,
    fs_offset: u64,
    lo_size: u64,
) -> Result<LoopDevice, InstallFailure> {
    let start = time::Instant::now();
    let loop_device = lc
        .next_free()
        .await
        .map_err(InstallFailure::LoopDeviceError)?;

    debug!("Using loop device {:?}", loop_device.path().await);

    loop_device
        .attach_file(fs_path, fs, fs_offset, lo_size, true, true)
        .map_err(InstallFailure::LoopDeviceError)?;

    if let Err(error) = loop_device.set_direct_io(true) {
        warn!("Failed to enable direct io: {:?}", error);
    }

    let losetup_duration = start.elapsed();
    debug!(
        "Loopback setup took {:.03}s",
        losetup_duration.as_fractional_secs(),
    );

    Ok(loop_device)
}

async fn veritysetup(
    dm: &dm::Dm,
    dm_dev: &str,
    dev: &str,
    verity: &VerityHeader,
    name: &str,
    verity_hash: &str,
    size: u64,
) -> Result<PathBuf, InstallFailure> {
    debug!("Creating a read-only verity device (name: {})", &name);
    let start = time::Instant::now();
    let dm_device = dm
        .device_create(
            &name,
            &dm::DmOptions::new().set_flags(dm::DmFlags::DM_READONLY),
        )
        .await
        .map_err(InstallFailure::DeviceMapperProblem)?;

    let verity_table = format!(
        "{} {} {} {} {} {} {} {} {} {}",
        verity.version,
        dev,
        dev,
        verity.data_block_size,
        verity.hash_block_size,
        verity.data_blocks,
        verity.data_blocks + 1,
        verity.algorithm,
        verity_hash,
        verity.salt
    );
    let table = vec![(0, size / 512, "verity".to_string(), verity_table.clone())];

    let dm_dev = PathBuf::from(format!("{}{}", dm_dev, dm_device.id() & 0xFF));

    debug!("Verity-device used: {}", dm_dev.to_string_lossy());
    dm.table_load_flags(
        name,
        &table,
        dm::DmOptions::new().set_flags(dm::DmFlags::DM_READONLY),
    )
    .await
    .map_err(InstallFailure::DeviceMapperProblem)?;

    debug!("Resuming device");
    dm.device_suspend(&name, &dm::DmOptions::new())
        .await
        .map_err(InstallFailure::DeviceMapperProblem)?;

    debug!("Waiting for device {}", dm_dev.display());
    while !dm_dev.exists().await {
        task::sleep(std::time::Duration::from_millis(1)).await;
    }

    let veritysetup_duration = start.elapsed();
    debug!(
        "Verity setup took {:.03}s",
        veritysetup_duration.as_fractional_secs()
    );

    Ok(dm_dev)
}

async fn mount(dm_dev: &Path, root: &Path, r#type: &str) -> Result<(), InstallFailure> {
    let start = time::Instant::now();
    debug!(
        "Mount read-only {} filesystem on device {} to this location:{}",
        r#type,
        dm_dev.display(),
        root.display(),
    );
    linux_mount::mount(
        &dm_dev,
        &root,
        &r#type,
        linux_mount::MountFlags::MS_RDONLY,
        None,
    )
    .await?;

    let mount_duration = start.elapsed();
    debug!("Mounting took {:.03}s", mount_duration.as_fractional_secs());

    Ok(())
}
