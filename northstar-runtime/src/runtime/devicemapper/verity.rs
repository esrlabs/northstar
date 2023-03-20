/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// `dm::verity` module implements the "verity" target in the device mapper framework. Specifically,
// it provides `DmVerityTargetBuilder` struct which is used to construct a `DmVerityTarget` struct
// which is then given to `DeviceMapper` to create a mapper device.

use super::data_model::DataInit;
use anyhow::{bail, Context, Result};
use std::{io::Write, mem::size_of, path::Path};

use super::{util::*, DmTargetSpec};

// The UAPI for the verity target is here.
// https://www.kernel.org/doc/Documentation/device-mapper/verity.txt

/// Device-Mapper’s “verity” target provides transparent integrity checking of block devices using
/// a cryptographic digest provided by the kernel crypto API
pub struct DmVerityTarget(Box<[u8]>);

/// Version of the verity target spec.
pub enum DmVerityVersion {
    /// Only `1` is supported.
    V1,
}

/// The hash algorithm to use. SHA256 and SHA512 are supported.
#[allow(dead_code)]
pub enum DmVerityHashAlgorithm {
    /// sha with 256 bit hash
    SHA256,
    /// sha with 512 bit hash
    SHA512,
}

/// A builder that constructs `DmVerityTarget` struct.
pub struct DmVerityTargetBuilder<'a> {
    version: DmVerityVersion,
    data_device: Option<&'a Path>,
    data_size: u64,
    hash_device: Option<&'a Path>,
    hash_algorithm: DmVerityHashAlgorithm,
    root_digest: Option<&'a [u8]>,
    salt: Option<&'a [u8]>,
}

impl DmVerityTarget {
    /// flatten into slice
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> Default for DmVerityTargetBuilder<'a> {
    fn default() -> Self {
        DmVerityTargetBuilder {
            version: DmVerityVersion::V1,
            data_device: None,
            data_size: 0,
            hash_device: None,
            hash_algorithm: DmVerityHashAlgorithm::SHA256,
            root_digest: None,
            salt: None,
        }
    }
}

impl<'a> DmVerityTargetBuilder<'a> {
    /// Sets the device that will be used as the data device (i.e. providing actual data).
    pub fn data_device(&mut self, p: &'a Path, size: u64) -> &mut Self {
        self.data_device = Some(p);
        self.data_size = size;
        self
    }

    /// Sets the device that provides the merkle tree.
    pub fn hash_device(&mut self, p: &'a Path) -> &mut Self {
        self.hash_device = Some(p);
        self
    }

    /// Sets the hash algorithm that the merkle tree is using.
    pub fn hash_algorithm(&mut self, algo: DmVerityHashAlgorithm) -> &mut Self {
        self.hash_algorithm = algo;
        self
    }

    /// Sets the root digest of the merkle tree. The format is hexadecimal string.
    pub fn root_digest(&mut self, digest: &'a [u8]) -> &mut Self {
        self.root_digest = Some(digest);
        self
    }

    /// Sets the salt used when creating the merkle tree. Note that this is empty for merkle trees
    /// created following the APK signature scheme V4.
    pub fn salt(&mut self, salt: &'a [u8]) -> &mut Self {
        self.salt = Some(salt);
        self
    }

    /// Constructs a `DmVerityTarget`.
    pub fn build(&self) -> Result<DmVerityTarget> {
        // The `DmVerityTarget` struct actually is a flattened data consisting of a header and
        // body. The format of the header is `dm_target_spec` as defined in
        // include/uapi/linux/dm-ioctl.h. The format of the body, in case of `verity` target is
        // https://www.kernel.org/doc/Documentation/device-mapper/verity.txt
        //
        // Step 1: check the validity of the inputs and extra additional data (e.g. block size)
        // from them.
        let version = match self.version {
            DmVerityVersion::V1 => 1,
        };

        let data_device_path = self
            .data_device
            .context("data device is not set")?
            .to_str()
            .context("data device path is not encoded in utf8")?;
        let stat = fstat(self.data_device.unwrap())?; // safe; checked just above
        let data_block_size = stat.st_blksize as u64;
        let data_size = self.data_size;
        let num_data_blocks = data_size / data_block_size;

        let hash_device_path = self
            .hash_device
            .context("hash device is not set")?
            .to_str()
            .context("hash device path is not encoded in utf8")?;
        let stat = fstat(self.data_device.unwrap())?; // safe; checked just above
        let hash_block_size = stat.st_blksize;

        let hash_algorithm = match self.hash_algorithm {
            DmVerityHashAlgorithm::SHA256 => "sha256",
            DmVerityHashAlgorithm::SHA512 => "sha512",
        };

        let root_digest = if let Some(root_digest) = self.root_digest {
            hexstring_from(root_digest)
        } else {
            bail!("root digest is not set")
        };

        let salt = if self.salt.is_none() || self.salt.unwrap().is_empty() {
            "-".to_string() // Note. It's not an empty string!
        } else {
            hexstring_from(self.salt.unwrap())
        };

        // Step2: serialize the information according to the spec, which is ...
        // DmTargetSpec{...}
        // <version> <dev> <hash_dev>
        // <data_block_size> <hash_block_size>
        // <num_data_blocks> <hash_start_block>
        // <algorithm> <digest> <salt>
        // [<#opt_params> <opt_params>]
        // null terminator

        // TODO(jiyong): support the optional parameters... if needed.
        let mut body = String::new();
        use std::fmt::Write;
        write!(&mut body, "{} ", version)?;
        write!(&mut body, "{} ", data_device_path)?;
        write!(&mut body, "{} ", hash_device_path)?;
        write!(&mut body, "{} ", data_block_size)?;
        write!(&mut body, "{} ", hash_block_size)?;
        write!(&mut body, "{} ", num_data_blocks)?;
        write!(&mut body, "{} ", 0)?; // hash_start_block
        write!(&mut body, "{} ", hash_algorithm)?;
        write!(&mut body, "{} ", root_digest)?;
        write!(&mut body, "{}", salt)?;
        write!(&mut body, "\0")?; // null terminator

        let size = size_of::<DmTargetSpec>() + body.len();
        let aligned_size = (size + 7) & !7; // align to 8 byte boundaries
        let padding = aligned_size - size;
        let mut header = DmTargetSpec::new("verity")?;
        header.sector_start = 0;
        header.length = data_size / 512; // number of 512-byte sectors
        header.next = aligned_size as u32;

        let mut buf = Vec::with_capacity(aligned_size);
        buf.write_all(header.as_slice())?;
        buf.write_all(body.as_bytes())?;
        buf.write_all(vec![0; padding].as_slice())?;
        Ok(DmVerityTarget(buf.into_boxed_slice()))
    }
}
