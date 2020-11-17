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

use crate::{manifest::Manifest, runtime::error::InstallationError};
use ed25519_dalek::{ed25519::signature::Signature as EdSignature, PublicKey};
use fmt::Debug;
use log::trace;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fmt::{self},
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
};

#[cfg(any(target_os = "android", target_os = "linux"))]
mod linux;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use linux::{mount, mount_all, umount};

#[cfg(not(any(target_os = "android", target_os = "linux")))]
mod mock;
#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub use mock::{mount, mount_all, umount};

#[derive(Debug)]
pub struct Container {
    pub manifest: Manifest,
    pub root: PathBuf,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub dm_dev: PathBuf,
}

impl Container {
    pub fn is_resource_container(&self) -> bool {
        self.manifest.is_resource()
    }
}

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
    #[allow(unused)]
    pub fn from_str(
        file: &str,
        keys: &HashMap<String, PublicKey>,
    ) -> Result<Hashes, InstallationError> {
        let mut docs = file.splitn(2, "---");

        // Manifest hash and fs.img part
        let hashes = docs.next().ok_or_else(|| {
            InstallationError::SignatureFileInvalid("Could not read hashes section".to_string())
        })?;

        // Signature
        let next = docs.next().ok_or(InstallationError::MalformedSignature)?;
        let signature: Signature = serde_yaml::from_str::<SerdeSignature>(next)
            .map_err(|e| InstallationError::MalformedSignature)?
            .try_into()
            .map_err(|e| InstallationError::MalformedSignature)?;

        // Check signature
        let key = keys.get(&signature.key).ok_or_else(|| {
            InstallationError::KeyNotFound(format!("Key {} not found", &signature.key))
        })?;
        let signature = EdSignature::from_bytes(&signature.signature)
            .map_err(|e| InstallationError::MalformedSignature)?;
        key.verify_strict(&hashes.as_bytes(), &signature)
            .map_err(|e| {
                InstallationError::SignatureVerificationError(format!("Problem hash key: {}", e))
            })?;

        let hashes: Hashes = serde_yaml::from_str::<SerdeHashes>(hashes)
            .map_err(|e| {
                InstallationError::MalformedHashes(format!(
                    "Problem parsing the hash section: {}",
                    e
                ))
            })?
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
    type Error = InstallationError;
    fn try_from(s: SerdeSignature) -> Result<Signature, InstallationError> {
        let signature = base64::decode(s.signature).map_err(|_e| {
            InstallationError::SignatureFileInvalid("Signature base64 error".to_string())
        })?;
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
    type Error = InstallationError;
    fn try_from(s: SerdeHashes) -> Result<Hashes, InstallationError> {
        let manifest_hash = s
            .manifest
            .get("hash")
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                InstallationError::MalformedManifest("Missing hash for manifest.yaml".to_string())
            })?;

        let fs_hash = s.fs.get("hash").map(ToOwned::to_owned).ok_or_else(|| {
            InstallationError::MalformedHashes("Missing hash for fs.img".to_string())
        })?;

        let fs_verity_hash =
            s.fs.get("verity-hash")
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    InstallationError::MalformedHashes("Missing verity-hash for fs.img".to_string())
                })?;

        let fs_verity_offset = s
            .fs
            .get("verity-offset")
            .ok_or_else(|| {
                InstallationError::MalformedHashes("Missing verity-offset for fs.img".to_string())
            })
            .and_then(|s| {
                str::parse::<u64>(s).map_err(|e| {
                    InstallationError::MalformedHashes(format!(
                        "Failed to parse verity-offset: {}",
                        e
                    ))
                })
            })?;

        Ok(Hashes {
            manifest_hash,
            fs_hash,
            fs_verity_hash,
            fs_verity_offset,
        })
    }
}

const MANIFEST: &str = "manifest.yaml";
const SIGNATURE: &str = "signature.yaml";
const FS_IMAGE: &str = "fs.img";

struct ArchiveReader<'a> {
    archive: zip::ZipArchive<std::io::BufReader<std::fs::File>>,
    signing_keys: &'a HashMap<String, PublicKey>,
}

pub fn read_manifest(
    npk: &Path,
    signing_keys: &HashMap<String, PublicKey>,
) -> Result<Manifest, InstallationError> {
    let mut archive_reader = ArchiveReader::new(&npk, &signing_keys)?;
    archive_reader.extract_manifest_from_archive()
}

impl<'a> ArchiveReader<'a> {
    fn new(
        npk: &Path,
        signing_keys: &'a HashMap<String, PublicKey>,
    ) -> Result<Self, InstallationError> {
        let file = std::fs::File::open(&npk).map_err(|e| InstallationError::Io {
            context: format!("Failed to open {:?} ({})", npk, e),
            error: e,
        })?;

        let reader: std::io::BufReader<std::fs::File> = std::io::BufReader::new(file);
        let archive: zip::ZipArchive<std::io::BufReader<std::fs::File>> =
            zip::ZipArchive::new(reader).map_err(InstallationError::Zip)?;
        Ok(Self {
            archive,
            signing_keys,
        })
    }

    pub fn extract_fs_start_and_size(&mut self) -> Result<(u64, u64), InstallationError> {
        let f = self.archive.by_name(FS_IMAGE).map_err(|e| {
            InstallationError::ArchiveError(format!("Failed to find file-system {}", e))
        })?;

        Ok((f.data_start(), f.size()))
    }

    pub fn extract_hashes(&mut self) -> Result<Hashes, InstallationError> {
        let mut signature_file = self
            .archive
            .by_name(SIGNATURE)
            // .with_context(|| "Failed to read signature".to_string())
            .map_err(InstallationError::Zip)?;
        let mut signature = String::new();
        signature_file
            .read_to_string(&mut signature)
            .map_err(|_e| {
                InstallationError::SignatureFileInvalid("Could not read signature file".to_string())
            })?;
        Hashes::from_str(&signature, &self.signing_keys)
    }

    pub fn extract_manifest_from_archive(&mut self) -> Result<Manifest, InstallationError> {
        let hashes = self.extract_hashes()?;
        let mut manifest_file = self.archive.by_name(MANIFEST).map_err(|e| {
            InstallationError::ArchiveError(format!("Failed to read manifest ({})", e))
        })?;

        let mut manifest_string = String::new();
        manifest_file
            .read_to_string(&mut manifest_string)
            .map_err(|e| {
                InstallationError::ArchiveError(format!("Error reading manifest file: {}", e))
            })?;
        let digest = sha2::Sha256::digest(manifest_string.as_bytes());
        let decoded_manifest_hash = hex::decode(&hashes.manifest_hash).map_err(|e| {
            InstallationError::ArchiveError(format!("Error decoding manifest hash: {}", e))
        })?;
        if decoded_manifest_hash != digest.as_slice() {
            return Err(InstallationError::HashInvalid(
                "Invalid manifest hash".to_string(),
            ));
        }
        Manifest::from_str(&manifest_string).map_err(|e| {
            InstallationError::MalformedManifest(format!("Error parsing manifest file: {}", e))
        })
    }
}

#[test]
fn test_signature_parsing() -> std::io::Result<()> {
    let signature = "manifest.yaml:
  hash: 0cbc141c2ef274989683d9ec03edcf41c57688ef5c422c647239328de2c3f306
fs.img:
  hash: 3920b5cdb472a9b82a31a77192d9de8c0200718c6eeaf0f6c5cabba80de852f3
  verity-hash: 39d01c334d0800e39674005ff52238160b36078dd44839cfefa89f1d12cc3cfa
  verity-offset: 4435968
---
key: north
signature: +lUTeD1YQDAmZTa32Ni1EhztzpaOgN329kNbWEo5NA+hbKRQjIaP6jXffHWSL3x/glZ54dEm7yjXtjqFonT7BQ==
";

    let key_bytes = base64::decode("DKkTMfhuqOggK4Bx3H8cgDAz3LH1AhiKu9gknCGOsCE=")
        .expect("Cannot parse base64 key");
    let key = PublicKey::from_bytes(&key_bytes).expect("Cannot parse public key");
    let mut signing_keys: HashMap<String, PublicKey> = HashMap::new();
    signing_keys.insert("north".to_string(), key);
    let s = Hashes::from_str(signature, &signing_keys).expect("Failed to parse signature");

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
