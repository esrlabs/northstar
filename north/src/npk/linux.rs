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

use super::{Container, Hashes};
use crate::{
    linux::{
        device_mapper as dm,
        loopdev::{LoopControl, LoopDevice},
        mount,
    },
    manifest::{Manifest, Name, Version},
    state::State,
};
use anyhow::{anyhow, Context, Result};
use async_std::{
    fs, io,
    path::{Path, PathBuf},
    prelude::*,
    task,
};
use floating_duration::TimeAsFloat;
use fmt::Debug;
use futures::stream::StreamExt;
use log::*;
use nix::unistd::{self, chown};
use sha2::Digest;
use std::{
    fmt::{self},
    io::Read,
    str::FromStr,
    time,
};

const MANIFEST: &str = "manifest.yaml";
const FS_IMAGE: &str = "fs.img";
const SIGNATURE: &str = "signature.yaml";

struct VerityHeader {
    pub header: Vec<u8>,
    pub version: u32,
    pub algorithm: String,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_blocks: u64,
    pub salt: String,
}

pub async fn install_all(state: &mut State, dir: &Path) -> Result<()> {
    info!("Installing containers from {}", dir.display());

    lazy_static::lazy_static! {
        static ref RE: regex::Regex = regex::Regex::new(
            format!(
                r"^.*-{}-\d+\.\d+\.\d+\.(npk|tgz)$",
                env!("VERGEN_TARGET_TRIPLE")
            )
            .as_str(),
        )
        .expect("Invalid regex");
    }

    let npks = fs::read_dir(&dir)
        .await
        .with_context(|| format!("Failed to read {}", dir.display()))?
        .filter_map(move |d| async move { d.ok() })
        .map(|d| d.path())
        .filter_map(move |d| async move {
            if RE.is_match(&d.display().to_string()) {
                Some(d)
            } else {
                None
            }
        });

    let dm = state.config.devices.device_mapper.clone();
    let dm = dm::Dm::new(&dm).context("Failed to open device mapper")?;
    let lc: PathBuf = state.config.devices.loop_control.clone().into();
    let lc = LoopControl::open(&lc, &state.config.devices.loop_dev)
        .await
        .context("Failed to open loop control")?;

    let mut npks = Box::pin(npks);
    while let Some(npk) = npks.next().await {
        install_internal(state, &dm, &lc, &npk).await?;
    }
    Ok(())
}

#[allow(dead_code)]
pub async fn install(state: &mut State, npk: &Path) -> Result<(Name, Version)> {
    debug!("Installing {}", npk.display());

    let dm = &state.config.devices.device_mapper.clone();
    let dm = dm::Dm::new(&dm).context("Failed to open device mapper")?;
    let lc: PathBuf = state.config.devices.loop_control.clone().into();
    let lc = LoopControl::open(&lc, &state.config.devices.loop_dev)
        .await
        .context("Failed to open loop control")?;

    let (name, version) = install_internal(state, &dm, &lc, npk).await?;

    Ok((name, version))
}

#[allow(dead_code)]
pub async fn uninstall(container: &Container) -> Result<()> {
    debug!("Unmounting {}", container.root.display());
    mount::unmount(&container.root).await?;
    debug!("Removing {}", container.root.display());
    fs::remove_dir_all(&container.root)
        .await
        .with_context(|| format!("Failed to remove {}", container.root.display()))?;
    Ok(())
}

async fn install_internal(
    state: &mut State,
    dm: &dm::Dm,
    lc: &LoopControl,
    npk: &Path,
) -> Result<(Name, Version)> {
    let start = time::Instant::now();

    if let Some(npk_name) = npk.file_name() {
        info!("Loading {}", npk_name.to_string_lossy());
    }

    let file =
        std::fs::File::open(&npk).with_context(|| format!("Failed to open {}", npk.display()))?;
    let reader = std::io::BufReader::new(file);
    let mut archive = zip::ZipArchive::new(reader).context("Failed to read zip")?;

    debug!("Loading hashes");
    let hashes = {
        let mut signature_file = archive
            .by_name(SIGNATURE)
            .with_context(|| format!("Failed to read signature from {}", npk.display()))?;
        let mut signature = String::new();
        signature_file.read_to_string(&mut signature)?;
        Hashes::from_str(&signature, &state.signing_keys).context("Failed to load hashes")?
    };

    let manifest = {
        let mut manifest_file = archive
            .by_name(MANIFEST)
            .with_context(|| format!("Failed to read manifest from {}", npk.display()))?;
        let mut manifest = String::new();
        manifest_file.read_to_string(&mut manifest)?;
        let digest = sha2::Sha256::digest(manifest.as_bytes());
        if hex::decode(&hashes.manifest_hash)? != digest.as_slice() {
            return Err(anyhow!("Invalid manifest hash"));
        }
        Manifest::from_str(&manifest)?
    };
    debug!("Manifest loaded for \"{}\"", manifest.name);
    if let Some(resources) = &manifest.resources {
        debug!("Referencing {} resources:", resources.len());
        for res in resources {
            debug!("- {}", res);
        }
    }

    let (fs_offset, fs_size) = {
        let f = archive
            .by_name(FS_IMAGE)
            .with_context(|| format!("Failed to read manifest from {}", npk.display()))?;
        (f.data_start(), f.size())
    };

    let fs = archive.into_inner().into_inner();
    let mut fs: fs::File = fs.into(); // the npk file

    let verity = read_verity_header(&mut fs, fs_offset, hashes.fs_verity_offset).await?;
    assert_eq!(&verity.header, b"verity");
    assert_eq!(verity.version, 1);
    assert_eq!(&verity.algorithm, &"sha256");

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
                .context("Failed to create mountpoint")?;
        }

        let name = format!("north_{}_{}", manifest.name, manifest.version);

        setup_and_mount(
            dm,
            lc,
            &verity,
            &name,
            hashes.fs_verity_offset,
            &hashes.fs_verity_hash,
            &npk,
            &mut fs,
            fs_offset,
            fs_size,
            &root,
        )
        .await?;

        let data = if state.config.global_data_dir {
            state.config.directories.data_dir.clone()
        } else {
            state.config.directories.data_dir.join(&manifest.name)
        };
        let data = PathBuf::from(data);
        if !data.exists().await {
            fs::create_dir_all(&data)
                .await
                .with_context(|| format!("Failed to create {}", data.display()))?;
            let data: &std::path::Path = data.as_path().into();
            chown(
                data,
                Some(unistd::Uid::from_raw(crate::SYSTEM_UID)),
                Some(unistd::Gid::from_raw(crate::SYSTEM_GID)),
            )
            .with_context(|| {
                format!(
                    "Failed to chown {} to {}:{}",
                    data.display(),
                    crate::SYSTEM_UID,
                    crate::SYSTEM_GID
                )
            })?;
        }

        let data = if state.config.global_data_dir {
            state.config.directories.data_dir.clone()
        } else {
            state.config.directories.data_dir.join(&manifest.name)
        };
        let data = PathBuf::from(data);

        let container = Container {
            root: root.into(),
            data,
            manifest,
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

#[allow(clippy::too_many_arguments)]
async fn setup_and_mount(
    dm: &dm::Dm,
    lc: &LoopControl,
    verity: &VerityHeader,
    name: &str,
    dm_device_size: u64,
    verity_hash: &str,
    fs_path: &Path,
    mut fs: &mut fs::File,
    fs_offset: u64,
    lo_size: u64,
    root: &Path,
) -> Result<()> {
    let fs_type = get_fs_type(&mut fs, fs_offset).await?;

    let loop_device = losetup(lc, fs_path, fs, fs_offset, lo_size).await?;
    let loop_device_id = loop_device
        .dev_id()
        .await
        .map(|(major, minor)| format!("{}:{}", major, minor))?;

    let dm_dev = veritysetup(
        &dm,
        &loop_device_id,
        &verity,
        name,
        verity_hash,
        dm_device_size,
    )
    .await?;

    mount(dm_dev.as_path(), root, fs_type).await?;

    dm.device_remove(
        &name.to_string(),
        &dm::DmOptions::new().set_flags(dm::DmFlags::DM_DEFERRED_REMOVE),
    )
    .await
    .context("Failed to set defered remove flag")?;

    Ok(())
}

async fn get_fs_type(fs: &mut fs::File, fs_offset: u64) -> Result<&'static str> {
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
) -> Result<VerityHeader> {
    let mut header = [0u8; 512];
    fs.seek(std::io::SeekFrom::Start(fs_offset + verity_offset))
        .await?;
    fs.read_exact(&mut header).await?;
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
    ) = s
        .unpack(header.to_vec())
        .context("Failed to decode verity block")?;

    Ok(VerityHeader {
        header,
        version,
        algorithm: std::str::from_utf8(&algorithm)
            .context("Invalid algorithm in verity block")?
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
) -> Result<LoopDevice> {
    let start = time::Instant::now();
    let loop_device = lc
        .next_free()
        .await
        .context("Failed to acquire free loopdev")?;

    debug!(
        "Using loop device {}",
        loop_device.path().await.unwrap().display()
    );

    loop_device
        .attach_file(fs_path, fs, fs_offset, lo_size, true, true)
        .context("Failed to attach loopback")?;

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
    dev: &str,
    verity: &VerityHeader,
    name: &str,
    verity_hash: &str,
    size: u64,
) -> Result<PathBuf> {
    debug!("Creating a read-only verity device (name: {})", &name);
    let start = time::Instant::now();
    let dm_device = dm
        .device_create(
            &name,
            &dm::DmOptions::new().set_flags(dm::DmFlags::DM_READONLY),
        )
        .await
        .context("Failed to create device")?;

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

    let dm_dev = PathBuf::from(format!(
        "dm-{}",
        //SETTINGS.devices.device_mapper_dev, // TODO
        dm_device.id() & 0xFF
    ));

    debug!("Verity-device used: {}", dm_dev.to_string_lossy());
    dm.table_load_flags(
        name,
        &table,
        dm::DmOptions::new().set_flags(dm::DmFlags::DM_READONLY),
    )
    .await
    .context("Failed to load table")?;

    debug!("Resuming device");
    dm.device_suspend(&name, &dm::DmOptions::new())
        .await
        .context("Failed to suspend device")?;

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

async fn mount(dm_dev: &Path, root: &Path, r#type: &str) -> Result<()> {
    let start = time::Instant::now();
    debug!(
        "Mount read-only {} filesystem on device {} to this location:{}",
        r#type,
        dm_dev.display(),
        root.display(),
    );
    mount::mount(&dm_dev, &root, &r#type, mount::MountFlags::RDONLY, None)
        .await
        .with_context(|| format!("Failed to mount {} on {}", dm_dev.display(), root.display()))?;

    let mount_duration = start.elapsed();
    debug!("Mounting took {:.03}s", mount_duration.as_fractional_secs());

    Ok(())
}
