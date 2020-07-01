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

use anyhow::{anyhow, Context, Error, Result};
use fmt::Debug;
use log::{debug, trace};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fmt::{self},
};

#[derive(Eq, PartialEq, Debug)]
pub struct Hashes {
    pub manifest_hash: String,
    pub fs_hash: String,
    pub fs_verity_hash: String,
    pub fs_verity_offset: u64,
}

struct Signature {
    pub key: String,
    pub signature: Vec<u8>,
}

impl Hashes {
    pub fn from_str(file: &str) -> Result<Hashes, Error> {
        // sha256 of signature.yaml
        let mut hasher = sha2::Sha256::new();
        hasher.update(file.as_bytes());
        let _digest = format!("{:x}", hasher.finalize());

        let mut docs = file.split("---");

        // Manifest hash and fs.img part
        let hashes = docs
            .next()
            .ok_or_else(|| anyhow!("Malformed signature.yaml"))?;

        // Signature
        let signature: Signature = serde_yaml::from_str::<SerdeSignature>(
            docs.next().ok_or_else(|| anyhow!("Malformed signature"))?,
        )?
        .try_into()?;

        // Check signature
        debug!("Using key {}", signature.key);

        // TODO verify hashes

        let hashes: Hashes = serde_yaml::from_str::<SerdeHashes>(hashes)
            .context("Failed to parse signature")?
            .try_into()?;

        trace!("manifest.yaml hash is {}", hashes.manifest_hash);
        trace!("fs.img hash is {}", hashes.fs_hash);
        trace!("fs.img verity hash is {}", hashes.fs_verity_hash);
        trace!("fs.img verity offset is {}", hashes.fs_verity_offset);

        Ok(hashes)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SerdeSignature {
    pub key: String,
    pub signature: String,
}

impl TryFrom<SerdeSignature> for Signature {
    type Error = Error;

    fn try_from(s: SerdeSignature) -> Result<Signature, Error> {
        let signature = base64::decode(s.signature).context("Signature base64 error")?;
        Ok(Signature {
            key: s.key,
            signature,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SerdeHashes {
    #[serde(rename(serialize = "manifest.yaml"))]
    #[serde(rename(deserialize = "manifest.yaml"))]
    manifest: HashMap<String, String>,
    #[serde(rename(serialize = "fs.img"))]
    #[serde(rename(deserialize = "fs.img"))]
    fs: HashMap<String, String>,
}

impl TryFrom<SerdeHashes> for Hashes {
    type Error = Error;
    fn try_from(s: SerdeHashes) -> Result<Hashes, Error> {
        let manifest_hash = s
            .manifest
            .get("hash")
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow!("Missing hash for manifest.yaml"))?;

        let fs_hash =
            s.fs.get("hash")
                .map(ToOwned::to_owned)
                .ok_or_else(|| anyhow!("Missing hash for fs.img"))?;

        let fs_verity_hash =
            s.fs.get("verity-hash")
                .map(ToOwned::to_owned)
                .ok_or_else(|| anyhow!("Missing verity-hash for fs.img"))?;

        let fs_verity_offset = s
            .fs
            .get("verity-offset")
            .ok_or_else(|| anyhow!("Missing verity-hash for fs.img"))
            .and_then(|s| {
                str::parse::<u64>(s).map_err(|e| anyhow!("Failed to parse verity-offset: {}", e))
            })?;

        Ok(Hashes {
            manifest_hash,
            fs_hash,
            fs_verity_hash,
            fs_verity_offset,
        })
    }
}

#[async_std::test]
async fn test_signature_parsing() -> std::io::Result<()> {
    let signature = "
manifest.yaml:
  hash: 0cbc141c2ef274989683d9ec03edcf41c57688ef5c422c647239328de2c3f306
fs.img:
  hash: 3920b5cdb472a9b82a31a77192d9de8c0200718c6eeaf0f6c5cabba80de852f3
  verity-hash: 39d01c334d0800e39674005ff52238160b36078dd44839cfefa89f1d12cc3cfa
  verity-offset: 4435968
---
key: north
signature: +lUTeD1YQDAmZTa32Ni1EhztzpaOgN329kNbWEo5NA+hbKRQjIaP6jXffHWSL3x/glZ54dEm7yjXtjqFonT7BQ==
";

    let s = Hashes::from_str(signature).expect("Failed to parse signature");

    assert_eq!(
        s.manifest_hash,
        "0cbc141c2ef274989683d9ec03edcf41c57688ef5c422c647239328de2c3f306"
    );
    assert_eq!(
        s.fs_hash,
        "3920b5cdb472a9b82a31a77192d9de8c0200718c6eeaf0f6c5cabba80de852f3"
    );
    assert_eq!(
        s.fs_verity_hash,
        "39d01c334d0800e39674005ff52238160b36078dd44839cfefa89f1d12cc3cfa"
    );
    assert_eq!(s.fs_verity_offset, 4_435_968);
    Ok(())
}
