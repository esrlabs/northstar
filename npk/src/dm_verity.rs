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

use byteorder::{LittleEndian, ReadBytesExt};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    io,
    io::{Read, SeekFrom::Start},
};

use std::{io::Seek, path::Path};
use thiserror::Error;
use tokio::{
    fs::{File, OpenOptions},
    io::AsyncWriteExt,
};
use uuid::Uuid;

pub const SHA256_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 4096;

pub type Sha256Digest = [u8; SHA256_SIZE];
pub type Salt = Sha256Digest;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid verity header")]
    InvalidHeader,
    #[error("Unsupported verity version {0}")]
    UnsupportedVersion(u32),
    #[error("Unsupported verity algorithm")]
    UnsupportedAlgorithm(),
    #[error("Error generating hash tree: {0}")]
    HashTree(String),
    #[error("Error creating valid uuid")]
    Uuid,
    #[error("OS error: {context}")]
    Os {
        context: String,
        #[source]
        error: std::io::Error,
    },
}

// https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMVerity#verity-superblock-format
#[derive(Debug, Clone)]
pub struct VerityHeader {
    pub header: [u8; 8],
    pub version: u32,
    pub hash_type: u32,
    pub uuid: [u8; 16],
    pub algorithm: [u8; 32],
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_blocks: u64,
    pub salt_size: u16,
    pub salt: [u8; 256],
}

impl VerityHeader {
    pub const HEADER: &'static [u8; 6] = b"verity";
    pub const ALGORITHM: &'static [u8; 6] = b"sha256";
    pub const VERITY_VERSION: u32 = 1;

    fn new(uuid: &[u8; 16], data_blocks: u64, salt_size: u16, salt: &Salt) -> VerityHeader {
        let mut padded_header = [0u8; 8];
        padded_header[..VerityHeader::HEADER.len()].copy_from_slice(VerityHeader::HEADER);
        let mut padded_algorithm = [0u8; 32];
        padded_algorithm[..VerityHeader::ALGORITHM.len()].copy_from_slice(VerityHeader::ALGORITHM);
        let mut padded_salt = [0u8; 256];
        padded_salt[..salt.len()].copy_from_slice(&salt.to_vec());
        VerityHeader {
            header: padded_header,
            version: 1,
            hash_type: 1,
            uuid: *uuid,
            algorithm: padded_algorithm,
            data_block_size: BLOCK_SIZE as u32,
            hash_block_size: BLOCK_SIZE as u32,
            data_blocks,
            salt_size,
            salt: padded_salt,
        }
    }

    pub fn from_bytes<T: Read>(src: &mut T) -> Result<VerityHeader, Error> {
        || -> Result<VerityHeader, std::io::Error> {
            let mut header = [0u8; 8];
            src.read_exact(&mut header)?;
            let version = src.read_u32::<LittleEndian>()?;
            let hash_type = src.read_u32::<LittleEndian>()?;
            let mut uuid = [0u8; 16];
            src.read_exact(&mut uuid)?;
            let mut algorithm = [0u8; 32];
            src.read_exact(&mut algorithm)?;
            let data_block_size = src.read_u32::<LittleEndian>()?;
            let hash_block_size = src.read_u32::<LittleEndian>()?;
            let data_blocks = src.read_u64::<LittleEndian>()?;
            let salt_size = src.read_u16::<LittleEndian>()?;
            io::copy(&mut src.take(6), &mut io::sink())?; // skip padding
            let mut salt = [0u8; 256];
            src.read_exact(&mut salt)?;
            Ok(VerityHeader {
                header,
                version,
                hash_type,
                uuid,
                algorithm,
                data_block_size,
                hash_block_size,
                data_blocks,
                salt_size,
                salt,
            })
        }()
        .map_err(|e| Error::Os {
            context: "Failed to read verity header".to_string(),
            error: e,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut raw_sb: Vec<u8> = vec![];
        raw_sb.extend(&self.header);
        raw_sb.extend(&self.version.to_ne_bytes());
        raw_sb.extend(&self.hash_type.to_ne_bytes());
        raw_sb.extend(&self.uuid);
        raw_sb.extend(&self.algorithm);
        raw_sb.extend(&self.data_block_size.to_ne_bytes());
        raw_sb.extend(&self.hash_block_size.to_ne_bytes());
        raw_sb.extend(&self.data_blocks.to_ne_bytes());
        raw_sb.extend(&self.salt_size.to_ne_bytes());
        raw_sb.extend(&[0_u8; 6]); // padding
        raw_sb.extend(&self.salt);
        raw_sb.extend(vec![0u8; BLOCK_SIZE - raw_sb.len()]); // pad to block size
        raw_sb
    }

    pub fn check(&self) -> Result<(), Error> {
        if !self.header.starts_with(VerityHeader::HEADER) {
            Err(Error::InvalidHeader)
        } else if self.version != VerityHeader::VERITY_VERSION {
            Err(Error::UnsupportedVersion(self.version))
        } else if !self.algorithm.starts_with(VerityHeader::ALGORITHM) {
            Err(Error::UnsupportedAlgorithm())
        } else {
            Ok(())
        }
    }
}

/// Generate and append a dm-verity superblock
/// (https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMVerity#verity-superblock-format)
/// and a dm-verity hash_tree
/// https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMVerity#hash-tree
/// to the given file.
pub async fn append_dm_verity_block(fsimg: &Path, fsimg_size: u64) -> Result<Sha256Digest, Error> {
    let (level_offsets, tree_size) =
        calc_hash_tree_level_offsets(fsimg_size as usize, BLOCK_SIZE, SHA256_SIZE as usize);
    let (salt, root_hash, hash_tree) =
        gen_hash_tree(fsimg, fsimg_size, &level_offsets, tree_size).await?;
    append_superblock_and_hashtree(fsimg, fsimg_size, &salt, &hash_tree).await?;
    Ok(root_hash)
}

fn gen_salt() -> Salt {
    let mut salt: Salt = [0u8; SHA256_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

fn calc_hash_tree_level_offsets(
    image_size: usize,
    block_size: usize,
    digest_size: usize,
) -> (Vec<usize>, usize) {
    let mut level_offsets: Vec<usize> = vec![];
    let mut level_sizes: Vec<usize> = vec![];
    let mut tree_size = 0;
    let mut num_levels = 0;
    let mut rem_size = image_size;

    while rem_size > block_size {
        let num_blocks = (rem_size + block_size - 1) / block_size;
        let level_size = round_up_to_multiple(num_blocks * digest_size, block_size);

        level_sizes.push(level_size);
        tree_size += level_size;
        num_levels += 1;
        rem_size = level_size;
    }
    for n in 0..num_levels {
        let mut offset = 0;
        #[allow(clippy::needless_range_loop)]
        for m in (n + 1)..num_levels {
            offset += level_sizes[m];
        }
        level_offsets.push(offset);
    }

    (level_offsets, tree_size)
}

async fn gen_hash_tree(
    fsimg: &Path,
    image_size: u64,
    level_offsets: &[usize],
    tree_size: usize,
) -> Result<(Salt, Sha256Digest, Vec<u8>), Error> {
    // For a description of the overall hash tree generation logic see
    // https://source.android.com/security/verifiedboot/dm-verity#hash-tree

    let mut fsimg = &File::open(&fsimg)
        .await
        .map_err(|e| Error::Os {
            context: format!("Cannot open '{}'", &fsimg.display()),
            error: e,
        })?
        .into_std()
        .await;
    let mut hashes: Vec<[u8; SHA256_SIZE]> = vec![];
    let mut level_num = 0;
    let mut level_size = image_size;
    let mut hash_tree = vec![0_u8; tree_size];

    if image_size % BLOCK_SIZE as u64 != 0 {
        return Err(Error::HashTree(format!("Failed to generate verity has tree. The image size {} is not a multiple of the block size {}",
            image_size,
            BLOCK_SIZE)
        ));
    }

    // "1. Choose a random salt (hexadecimal encoding)."
    let salt = gen_salt();

    // "To form the hash, the system image is split at layer 0 into 4k blocks, each assigned a SHA256 hash.
    // Layer 1 is formed by joining only those SHA256 hashes into 4k blocks, resulting in a much smaller image.
    // Layer 2 is formed identically, with the SHA256 hashes of Layer 1.
    //
    // This is done until the SHA256 hashes of the previous layer can fit in a single block.
    // When get the SHA256 of that block, you have the root hash of the tree."
    // (https://source.android.com/security/verifiedboot/dm-verity#hash-tree)
    loop {
        hashes.clear();
        let mut rem_size = level_size;

        while rem_size > 0 {
            let mut sha256 = Sha256::new();
            sha256.update(salt);

            // "2. Unsparse your system image into 4k blocks."
            // "3. For each block, get its (salted) SHA256 hash."
            if level_num == 0 {
                // hash block of original file
                let offset = level_size - rem_size;
                let mut data = vec![0_u8; BLOCK_SIZE];
                fsimg.seek(Start(offset)).map_err(|e| Error::Os {
                    context: "Failed to seek in fs-image".to_string(),
                    error: e,
                })?;
                fsimg.read_exact(&mut data).map_err(|e| Error::Os {
                    context: "Failed to read from fs-image".to_string(),
                    error: e,
                })?;
                sha256.update(&data);
            } else {
                // hash block of previous level
                let offset = level_offsets[level_num - 1] + level_size as usize - rem_size as usize;
                sha256.update(&hash_tree[offset..offset + BLOCK_SIZE]);
            }

            rem_size -= BLOCK_SIZE as u64;
            hashes.push(sha256.finalize().into());
        }

        // the last iteration computed only a single hash which is our final root hash
        if hashes.len() == 1 {
            break;
        }

        // "4. Concatenate these hashes to form a level"
        let mut level = hashes.iter().flat_map(|s| s.iter().copied()).collect();

        // "5. Pad the level with 0s to a 4k block boundary."
        pad_to_block_size(&mut level);

        // "6. Concatenate the level to your hash tree."
        let offset = level_offsets[level_num];
        hash_tree[offset..offset + level.len()].copy_from_slice(level.as_slice());

        level_size = level.len() as u64;
        level_num += 1;
    }

    // "The result of this is a single hash, which is your root hash.
    // This and your salt are used during the construction of your dm-verity mapping table."
    let root_hash = hashes[0];
    Ok((salt, root_hash, hash_tree))
}

async fn append_superblock_and_hashtree(
    fsimg: &Path,
    fsimg_size: u64,
    salt: &Salt,
    hash_tree: &[u8],
) -> Result<(), Error> {
    let mut fsimg = OpenOptions::new()
        .write(true)
        .append(true)
        .open(&fsimg)
        .await
        .map_err(|e| Error::Os {
            context: format!("Cannot open '{}'", &fsimg.display()),
            error: e,
        })?;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(
        hex::decode(Uuid::new_v4().to_string().replace("-", ""))
            .map_err(|_e| Error::Uuid)?
            .as_slice(),
    );
    assert_eq!(fsimg_size % BLOCK_SIZE as u64, 0);
    let data_blocks = fsimg_size / BLOCK_SIZE as u64;
    let header = VerityHeader::new(&uuid, data_blocks, SHA256_SIZE as u16, &salt).to_bytes();
    fsimg.write_all(&header).await.map_err(|e| Error::Os {
        context: "Failed to write verity header".to_string(),
        error: e,
    })?;
    fsimg.write_all(&hash_tree).await.map_err(|e| Error::Os {
        context: "Failed to write verity hash tree".to_string(),
        error: e,
    })?;
    Ok(())
}

fn pad_to_block_size(data: &mut Vec<u8>) {
    let pad_size = round_up_to_multiple(data.len(), BLOCK_SIZE) - data.len();
    data.append(&mut vec![0_u8; pad_size]);
}

fn round_up_to_multiple(number: usize, multiple: usize) -> usize {
    number + ((multiple - (number % multiple)) % multiple)
}
