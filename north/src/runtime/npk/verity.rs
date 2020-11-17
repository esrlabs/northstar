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
            self, device_mapper as dm, inotify,
            loopdev::{self, LoopControl, LoopDevice},
            mount as linux_mount,
        },
        state::State,
    },
    Container,
};
use crate::{
    manifest::{Mount, Name, Version},
    runtime::npk::{self, ArchiveReader},
};
use floating_duration::TimeAsFloat;
use fmt::Debug;
use log::*;
use std::{
    fmt::{self},
    path::{Path, PathBuf},
    process,
};
use tokio::{fs, fs::metadata, io, prelude::*, stream::StreamExt, time};

const SUPPORTED_VERITY_VERSION: u32 = 1;

pub struct VerityHeader {
    pub header: Vec<u8>,
    pub version: u32,
    pub algorithm: String,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_blocks: u64,
    pub salt: String,
}

pub fn check_verity_config(verity: &VerityHeader) -> Result<(), linux::Error> {
    if &verity.header != b"verity" {
        return Err(linux::Error::NoVerityHeader);
    }
    if verity.version != SUPPORTED_VERITY_VERSION {
        return Err(linux::Error::UnexpectedVerityVersion(verity.version));
    }
    if verity.algorithm != "sha256" {
        return Err(linux::Error::UnexpectedVerityAlgorithm(
            verity.algorithm.clone(),
        ));
    }
    Ok(())
}

pub async fn get_fs_type(fs: &mut fs::File, fs_offset: u64) -> Result<&'static str, io::Error> {
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

pub async fn read_verity_header(
    fs: &mut fs::File,
    fs_offset: u64,
    verity_offset: u64,
) -> Result<VerityHeader, linux::Error> {
    let mut header = [0u8; 512];
    fs.seek(std::io::SeekFrom::Start(fs_offset + verity_offset))
        .await
        .map_err(|e| {
            linux::Error::VerityError(format!("Could not seek to verity header: {}", e))
        })?;
    fs.read_exact(&mut header)
        .await
        .map_err(|e| linux::Error::VerityError(format!("Could not read verity header: {}", e)))?;
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
        .map_err(|e| linux::Error::VerityError(format!("Failed to decode verity block: {}", e)))?;

    Ok(VerityHeader {
        header,
        version,
        algorithm: std::str::from_utf8(&algorithm)
            .map_err(|e| {
                linux::Error::VerityError(format!("Invalid algorithm in verity block: {}", e))
            })?
            .to_string(),
        data_block_size,
        hash_block_size,
        data_blocks,
        salt: hex::encode(&salt[..(salt_size as usize)]),
    })
}

pub async fn veritysetup(
    dm: &dm::Dm,
    dm_dev: &str,
    dev: &str,
    verity: &VerityHeader,
    name: &str,
    verity_hash: &str,
    size: u64,
) -> Result<PathBuf, linux::Error> {
    debug!("Creating a read-only verity device (name: {})", &name);
    let start = time::Instant::now();
    let dm_device = dm
        .device_create(
            &name,
            &dm::DmOptions::new().set_flags(dm::DmFlags::DM_READONLY),
        )
        .await
        .map_err(linux::Error::DeviceMapper)?;

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
    .map_err(linux::Error::DeviceMapper)?;

    debug!("Resuming device");
    dm.device_suspend(&name, &dm::DmOptions::new())
        .await
        .map_err(linux::Error::DeviceMapper)?;

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
