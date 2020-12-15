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

use crate::{
    manifest::{Manifest, Version},
    npk,
};
use ed25519_dalek::ed25519::signature::Signature as _;
use log::trace;
use serde::Deserialize;
use sha2::Digest;
use std::{io::Read, path::Path, str::FromStr};
use thiserror::Error;

const MANIFEST: &str = "manifest.yaml";
const SIGNATURE: &str = "signature.yaml";
const FS_IMAGE: &str = "fs.img";

pub type RepositoryId = String;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Archive error: {0}")]
    ArchiveError(String),
    #[error("Signature file invalid ({0})")]
    SignatureFileInvalid(String),
    #[error("Malformed signature")]
    MalformedSignature,
    #[error("Hashes malformed ({0})")]
    MalformedHashes(String),
    #[error("Manifest malformed ({0})")]
    MalformedManifest(String),
    #[error("Hash error: {0}")]
    HashInvalid(String),
    #[error("Problem verifying content with signature ({0})")]
    SignatureVerificationError(String),
    #[error("ZIP error")]
    Zip(#[from] zip::result::ZipError),
    #[error("Io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Eq, PartialEq, Debug)]
pub struct Hashes {
    pub manifest_hash: String,
    pub fs_hash: String,
    pub fs_verity_hash: String,
    pub fs_verity_offset: u64,
}

impl FromStr for Hashes {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct ManifestHash {
            hash: String,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct FsHashes {
            hash: String,
            verity_hash: String,
            verity_offset: u64,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct SerdeHashes {
            #[serde(rename = "manifest.yaml")]
            manifest: ManifestHash,
            #[serde(rename = "fs.img")]
            fs: FsHashes,
        }

        let hashes = serde_yaml::from_str::<SerdeHashes>(s)
            .map_err(|e| Error::MalformedHashes(format!("Problem deserializing hashes: {}", e)))?;

        trace!("manifest.yaml hash is {}", hashes.manifest.hash);
        trace!("fs.img hash is {}", hashes.fs.hash);
        trace!("fs.img verity hash is {}", hashes.fs.verity_hash);
        trace!("fs.img verity offset is {}", hashes.fs.verity_offset);

        Ok(Hashes {
            manifest_hash: hashes.manifest.hash,
            fs_hash: hashes.fs.hash,
            fs_verity_hash: hashes.fs.verity_hash,
            fs_verity_offset: hashes.fs.verity_offset,
        })
    }
}

fn verify(
    message: &[u8],
    signature: &ed25519_dalek::Signature,
    key: &ed25519_dalek::PublicKey,
) -> Result<(), Error> {
    key.verify_strict(message, &signature)
        .map_err(|e| Error::SignatureVerificationError(format!("Problem hash key: {}", e)))
}

fn decode_signature(s: &str) -> Result<ed25519_dalek::Signature, Error> {
    #[derive(Debug, Deserialize)]
    struct SerdeSignature {
        key: String,
        signature: String,
    }

    let de: SerdeSignature =
        serde_yaml::from_str::<SerdeSignature>(s).map_err(|_| Error::MalformedSignature)?;

    let signature = base64::decode(de.signature)
        .map_err(|_e| Error::SignatureFileInvalid("Signature base64 error".to_string()))?;

    ed25519_dalek::Signature::from_bytes(&signature).map_err(|_| Error::MalformedSignature)
}

pub struct ArchiveReader {
    archive: zip::ZipArchive<std::io::BufReader<std::fs::File>>,
}

impl ArchiveReader {
    pub fn new(npk: &Path) -> Result<Self, Error> {
        let file = std::fs::File::open(&npk)
            .map_err(|_e| Error::ArchiveError(format!("Failed to read file {}", npk.display())))?;

        let reader: std::io::BufReader<std::fs::File> = std::io::BufReader::new(file);
        let archive: zip::ZipArchive<std::io::BufReader<std::fs::File>> =
            zip::ZipArchive::new(reader).map_err(Error::Zip)?;
        Ok(Self { archive })
    }

    pub fn npk_version(&mut self) -> Result<Version, Error> {
        let comment = String::from_utf8(self.archive.comment().to_vec())
            .map_err(|e| Error::ArchiveError(format!("Failed to read NPK version string {}", e)))?;
        let mut split = comment.split(' ');
        while let Some(key) = split.next() {
            if let Some(value) = split.next() {
                if key == npk::NPK_VERSION_STR {
                    let version = Version::parse(&value).map_err(|e| {
                        Error::ArchiveError(format!("Failed to parse NPK version {}", e))
                    })?;
                    return Ok(version);
                }
            } else {
                return Err(Error::ArchiveError("Missing NPK version value".to_string()));
            }
        }
        Err(Error::ArchiveError(
            "Missing NPK version in ZIP comment".to_string(),
        ))
    }

    pub fn extract_fs_start_and_size(&mut self) -> Result<(u64, u64), Error> {
        let zip_file = self
            .archive
            .by_name(FS_IMAGE)
            .map_err(|e| Error::ArchiveError(format!("Failed to find file-system {}", e)))?;

        Ok((zip_file.data_start(), zip_file.size()))
    }

    pub fn manifest(&mut self) -> Result<Manifest, Error> {
        let mut manifest_string = String::new();
        self.archive
            .by_name(MANIFEST)
            .map_err(|e| Error::ArchiveError(format!("Failed to read manifest ({})", e)))?
            .read_to_string(&mut manifest_string)
            .map_err(|e| Error::ArchiveError(format!("Failed to read manifest file: {}", e)))?;
        Manifest::from_str(&manifest_string)
            .map_err(|e| Error::MalformedManifest(format!("Failed to parse manifest file: {}", e)))
    }

    pub fn extract_hashes(&mut self, key: &ed25519_dalek::PublicKey) -> Result<Hashes, Error> {
        let signature_content = self.read(SIGNATURE).map_err(|_e| {
            Error::SignatureFileInvalid("Failed to read signature file".to_string())
        })?;

        let mut sections = signature_content.split("---");
        let hashes_string = sections.next().unwrap_or_default();
        let signature_string = sections.next().unwrap_or_default();
        let signature = decode_signature(signature_string)?;
        verify(hashes_string.as_bytes(), &signature, key)?;

        Hashes::from_str(hashes_string)
    }

    pub fn extract_manifest(&mut self) -> Result<String, Error> {
        self.read(MANIFEST)
            .map_err(|_e| Error::ArchiveError("Failed to read manifest file".to_string()))
    }

    fn read(&mut self, name: &str) -> Result<String, Error> {
        let mut file = self.archive.by_name(name).map_err(Error::Zip)?;
        let mut content = String::new();
        file.read_to_string(&mut content).map_err(Error::Io)?;
        Ok(content)
    }

    pub fn extract_manifest_from_archive(
        &mut self,
        key: &ed25519_dalek::PublicKey,
    ) -> Result<Manifest, Error> {
        let hashes = self.extract_hashes(&key)?;

        let manifest_string = self.extract_manifest()?;
        let digest = sha2::Sha256::digest(manifest_string.as_bytes());
        let decoded_manifest_hash = hex::decode(&hashes.manifest_hash)
            .map_err(|e| Error::ArchiveError(format!("Error decoding manifest hash: {}", e)))?;
        if decoded_manifest_hash != digest.as_slice() {
            return Err(Error::HashInvalid("Invalid manifest hash".to_string()));
        }

        Manifest::from_str(&manifest_string)
            .map_err(|e| Error::MalformedManifest(format!("Failed to parse manifest file: {}", e)))
    }
}

#[test]
fn test_signature_parsing() -> Result<(), Error> {
    let hashes_string = "manifest.yaml:
  hash: 0cbc141c2ef274989683d9ec03edcf41c57688ef5c422c647239328de2c3f306
fs.img:
  hash: 3920b5cdb472a9b82a31a77192d9de8c0200718c6eeaf0f6c5cabba80de852f3
  verity-hash: 39d01c334d0800e39674005ff52238160b36078dd44839cfefa89f1d12cc3cfa
  verity-offset: 4435968
";

    let signature_string = "key: north
signature: +lUTeD1YQDAmZTa32Ni1EhztzpaOgN329kNbWEo5NA+hbKRQjIaP6jXffHWSL3x/glZ54dEm7yjXtjqFonT7BQ==
";

    let key_bytes = base64::decode("DKkTMfhuqOggK4Bx3H8cgDAz3LH1AhiKu9gknCGOsCE=")
        .expect("Cannot parse base64 key");
    let key = ed25519_dalek::PublicKey::from_bytes(&key_bytes).expect("Cannot parse public key");

    let signature = decode_signature(signature_string)?;
    verify(hashes_string.as_bytes(), &signature, &key)?;

    let s = Hashes::from_str(hashes_string).expect("Failed to parse signature");

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
