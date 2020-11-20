// Copyright (c) 2020 ESRLabs
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

#[macro_use]
extern crate structure;

pub mod archive;
pub mod dm_verity;
pub mod manifest;
pub mod npk;

use fmt::Debug;
use log::*;
use std::fmt;
use thiserror::Error;
use tokio::{fs, io, prelude::*};

const SUPPORTED_VERITY_VERSION: u32 = 1;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Verity device mapper problem ({0})")]
    Verity(String),
    #[error("Missing verity header")]
    NoVerityHeader,
    #[error("Unsupported verity version {0}")]
    UnexpectedVerityVersion(u32),
    #[error("Unsupported verity algorithm: {0}")]
    UnexpectedVerityAlgorithm(String),
    #[error("Problem with archive")]
    Archive(#[from] archive::Error),
}

pub struct VerityHeader {
    pub header: Vec<u8>,
    pub version: u32,
    pub algorithm: String,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_blocks: u64,
    pub salt: String,
}

pub fn check_verity_config(verity: &VerityHeader) -> Result<(), Error> {
    if &verity.header != b"verity" {
        return Err(Error::NoVerityHeader);
    }
    if verity.version != SUPPORTED_VERITY_VERSION {
        return Err(Error::UnexpectedVerityVersion(verity.version));
    }
    if verity.algorithm != "sha256" {
        return Err(Error::UnexpectedVerityAlgorithm(verity.algorithm.clone()));
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
) -> Result<VerityHeader, Error> {
    let mut header = [0u8; 512];
    fs.seek(std::io::SeekFrom::Start(fs_offset + verity_offset))
        .await
        .map_err(|e| Error::Verity(format!("Could not seek to verity header: {}", e)))?;
    fs.read_exact(&mut header)
        .await
        .map_err(|e| Error::Verity(format!("Could not read verity header: {}", e)))?;
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
        .map_err(|e| Error::Verity(format!("Failed to decode verity block: {}", e)))?;

    Ok(VerityHeader {
        header,
        version,
        algorithm: std::str::from_utf8(&algorithm)
            .map_err(|e| Error::Verity(format!("Invalid algorithm in verity block: {}", e)))?
            .to_string(),
        data_block_size,
        hash_block_size,
        data_blocks,
        salt: hex::encode(&salt[..(salt_size as usize)]),
    })
}
