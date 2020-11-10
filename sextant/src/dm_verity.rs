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

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Read, Seek, SeekFrom::Start, Write},
    path::Path,
};
use uuid::Uuid;

pub const SHA256_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 4096;

pub type Sha256Digest = [u8; SHA256_SIZE];
pub type Salt = Sha256Digest;

/// Generate and append a dm-verity superblock
/// (https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMVerity#verity-superblock-format)
/// and a dm-verity hash_tree
/// https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMVerity#hash-tree
/// to the given file.
pub fn append_dm_verity_block(fsimg_path: &Path, fsimg_size: u64) -> Result<Sha256Digest> {
    let (level_offsets, tree_size) =
        calc_hash_tree_level_offsets(fsimg_size as usize, BLOCK_SIZE, SHA256_SIZE as usize);
    let (salt, root_hash, hash_tree) = gen_hash_tree(
        &File::open(&fsimg_path)
            .with_context(|| format!("Cannot open '{}'", &fsimg_path.display()))?,
        fsimg_size,
        &level_offsets,
        tree_size,
    )
    .with_context(|| "Error while generating hash tree")?;
    append_superblock_and_hashtree(&fsimg_path, fsimg_size, &salt, &hash_tree)
        .with_context(|| "Error while writing verity header")?;
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

fn gen_hash_tree(
    image: &File,
    image_size: u64,
    level_offsets: &[usize],
    tree_size: usize,
) -> Result<(Salt, Sha256Digest, Vec<u8>)> {
    // For a description of the overall hash tree generation logic see
    // https://source.android.com/security/verifiedboot/dm-verity#hash-tree

    let mut hashes: Vec<[u8; SHA256_SIZE]> = vec![];
    let mut level_num = 0;
    let mut level_size = image_size;
    let mut hash_tree = vec![0_u8; tree_size];

    if image_size % BLOCK_SIZE as u64 != 0 {
        return Err(anyhow!(
            "Failed to generate verity has tree. The image size {} is not a multiple of the block size {}",
            image_size,
            BLOCK_SIZE
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
                let mut image_reader = BufReader::new(image);
                image_reader.seek(Start(offset))?;
                image_reader.read_exact(&mut data)?;
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

fn append_superblock_and_hashtree(
    fsimg_path: &Path,
    fsimg_size: u64,
    salt: &Salt,
    hash_tree: &[u8],
) -> Result<()> {
    let uuid = Uuid::new_v4();
    assert_eq!(fsimg_size % BLOCK_SIZE as u64, 0);
    let data_blocks = fsimg_size / BLOCK_SIZE as u64;

    let mut fsimg = OpenOptions::new()
        .write(true)
        .append(true)
        .open(&fsimg_path)
        .with_context(|| format!("Cannot open '{}'", &fsimg_path.display()))?;

    // write verity superblock
    // https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMVerity#verity-superblock-format
    const VERITY_SIGNATURE: &[u8; 8] = b"verity\x00\x00";
    const HASH_ALG_NAME: &[u8; 6] = b"sha256";
    let mut raw_sb: Vec<u8> = vec![];
    raw_sb.extend(VERITY_SIGNATURE);
    raw_sb.extend(&1_u32.to_ne_bytes()); // superblock version
    raw_sb.extend(&1_u32.to_ne_bytes()); // hash type 'normal'
    raw_sb.extend(&hex::decode(uuid.to_string().replace("-", ""))?);
    raw_sb.extend(HASH_ALG_NAME);
    raw_sb.extend(&[0_u8; 26]);
    raw_sb.extend(&(BLOCK_SIZE as u32).to_ne_bytes()); // data block in bytes
    raw_sb.extend(&(BLOCK_SIZE as u32).to_ne_bytes()); // hash block in bytes
    raw_sb.extend(&data_blocks.to_ne_bytes()); // number of data blocks
    raw_sb.extend(&(SHA256_SIZE as u16).to_ne_bytes()); // salt size
    raw_sb.extend(&[0_u8; 6]); // padding
    raw_sb.extend(salt);
    raw_sb.extend(&vec![0_u8; 256 - salt.len()]); // padding
    fsimg.write_all(&raw_sb)?;

    fsimg.write_all(vec![0u8; BLOCK_SIZE - raw_sb.len()].as_slice())?; // pad to BLOCK_SIZE
    fsimg.write_all(&hash_tree)?;
    Ok(())
}

fn pad_to_block_size(data: &mut Vec<u8>) {
    let pad_size = round_up_to_multiple(data.len(), BLOCK_SIZE) - data.len();
    data.append(&mut vec![0_u8; pad_size]);
}

fn round_up_to_multiple(number: usize, multiple: usize) -> usize {
    number + ((multiple - (number % multiple)) % multiple)
}
