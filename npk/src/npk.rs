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

pub use crate::npk;
use crate::{
    dm_verity,
    dm_verity::{append_dm_verity_block, Error as VerityError, VerityHeader, BLOCK_SIZE},
    manifest::{Manifest, Mount, MountFlag, Version},
};
use ed25519_dalek::{
    ed25519::signature::Signature, Keypair, PublicKey, SecretKey, SignatureError, Signer,
    SECRET_KEY_LENGTH,
};
use itertools::Itertools;
use rand::rngs::OsRng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    fs::File,
    io,
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};
use tempfile::TempDir;
use thiserror::Error;
use zip::{result::ZipError, ZipArchive};

// Binaries
pub const MKSQUASHFS_BIN: &str = "mksquashfs";
pub const UNSQUASHFS_BIN: &str = "unsquashfs";

// First half of version string in ZIP comment
pub const NPK_VERSION_STR: &str = "npk_version:";

// User and group id for squashfs pseudo directories ('/dev', '/proc', '/tmp' etc.)
const PSEUDO_DIR_UID: u32 = 1000;
const PSEUDO_DIR_GID: u32 = 1000;

// File name and directory components
const NPK_EXT: &str = "npk";
const FS_IMG_BASE: &str = "fs";
const FS_IMG_EXT: &str = "img";
pub const FS_IMG_NAME: &str = "fs.img";
const MANIFEST_BASE: &str = "manifest";
const MANIFEST_EXT: &str = "yaml";
pub const MANIFEST_NAME: &str = "manifest.yaml";
pub const SIGNATURE_NAME: &str = "signature.yaml";
const ROOT_DIR_NAME: &str = "root";

#[derive(Error, Debug)]
pub enum Error {
    #[error("Manifest error: {0}")]
    Manifest(String),
    #[error("File operation error: {0}")]
    Io(String),
    #[error("Squashfs error: {0}")]
    Squashfs(String),
    #[error("Archive error: {context}")]
    Zip {
        context: String,
        #[source]
        error: ZipError,
    },
    #[error("Verity error")]
    Verity(#[source] VerityError),
    #[error("OS error: {context}")]
    Os {
        context: String,
        #[source]
        error: std::io::Error,
    },
    #[error("Key error: {context}")]
    Key {
        context: String,
        #[source]
        error: SignatureError,
    },
    #[error("Manifest malformed: {0}")]
    MalformedManifest(String),
    #[error("Hashes malformed: {0}")]
    MalformedHashes(String),
    #[error("Signature malformed: {0}")]
    MalformedSignature(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
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

        Ok(Hashes {
            manifest_hash: hashes.manifest.hash,
            fs_hash: hashes.fs.hash,
            fs_verity_hash: hashes.fs.verity_hash,
            fs_verity_offset: hashes.fs.verity_offset,
        })
    }
}

pub struct Npk<R: io::Read + io::Seek> {
    inner: zip::ZipArchive<R>,
}

impl<R: io::Read + io::Seek> Npk<R> {
    pub fn new(npk: R) -> Result<Self, Error> {
        let zip = zip::ZipArchive::new(npk).map_err(|e| Error::Zip {
            context: "Failed to parse ZIP format of NPK".to_string(),
            error: e,
        })?;
        Ok(Self { inner: zip })
    }

    pub fn manifest(&mut self) -> Result<Manifest, Error> {
        if let Ok(mut file) = self.inner.by_name(&MANIFEST_NAME) {
            let mut content = String::new();
            file.read_to_string(&mut content).map_err(|e| Error::Os {
                context: "Failed to read manifest from file".to_string(),
                error: e,
            })?;
            Manifest::from_str(&content)
                .map_err(|e| Error::Manifest(format!("Failed to parse manifest file: {}", e)))
        } else {
            Err(Error::Io(format!(
                "Failed to locate {} in ZIP file",
                &MANIFEST_NAME
            )))
        }
    }

    /// contains the hashes and the key/signature pair
    fn signature_yaml(&mut self) -> Result<String, Error> {
        if let Ok(mut file) = self.inner.by_name(&SIGNATURE_NAME) {
            let mut content = String::new();
            file.read_to_string(&mut content).map_err(|e| Error::Os {
                context: "Failed to read signature from file".to_string(),
                error: e,
            })?;
            Ok(content)
        } else {
            Err(Error::Io(format!(
                "Failed to locate {} in ZIP file",
                &SIGNATURE_NAME
            )))
        }
    }

    pub fn hashes(&mut self) -> Result<Hashes, Error> {
        let sign_yaml = self.signature_yaml()?;
        let hashes_string = sign_yaml.split("---").next().unwrap_or_default();
        Hashes::from_str(hashes_string).map_err(|_e| {
            Error::MalformedHashes("Failed to read hashes from YAML file".to_string())
        })
    }

    pub fn signature(&mut self) -> Result<ed25519_dalek::Signature, Error> {
        #[derive(Debug, Deserialize)]
        struct SerdeSignature {
            key: String,
            signature: String,
        }

        let yaml = self.signature_yaml()?;
        let sign_string = yaml.split("---").nth(1).unwrap_or_default();
        let sign_serde = serde_yaml::from_str::<SerdeSignature>(sign_string).map_err(|e| {
            Error::MalformedSignature(format!("Failed to parse signature YAML format: {}", e))
        })?;
        let sign_bytes = base64::decode(sign_serde.signature).map_err(|e| {
            Error::MalformedSignature(format!("Failed to decode signature base 64 format: {}", e))
        })?;
        ed25519_dalek::Signature::from_bytes(&sign_bytes).map_err(|e| {
            Error::MalformedSignature(format!("Failed to parse signature ed25519 format: {}", e))
        })
    }

    pub fn verify(&mut self, key: &ed25519_dalek::PublicKey) -> Result<(), Error> {
        let sign_yaml = self.signature_yaml()?;
        let hashes_string = sign_yaml.split("---").next().unwrap_or_default();
        let signature = self.signature()?;
        key.verify_strict(hashes_string.as_bytes(), &signature)
            .map_err(|_e| Error::InvalidSignature("Invalid signature".to_string()))
    }

    pub fn version(&self) -> Result<Version, Error> {
        let comment = String::from_utf8(self.inner.comment().to_vec())
            .map_err(|e| Error::Manifest(format!("Failed to read NPK version string {}", e)))?;
        let mut split = comment.split(' ');
        while let Some(key) = split.next() {
            if let Some(value) = split.next() {
                if key == npk::NPK_VERSION_STR {
                    let version = Version::parse(&value).map_err(|e| {
                        Error::Manifest(format!("Failed to parse NPK version {}", e))
                    })?;
                    return Ok(version);
                }
            } else {
                return Err(Error::Manifest("Missing NPK version value".to_string()));
            }
        }
        Err(Error::Manifest(
            "Missing NPK version in ZIP comment".to_string(),
        ))
    }

    pub fn fsimg_offset(&mut self) -> Result<u64, Error> {
        if let Ok(fsimg) = self.inner.by_name(&FS_IMG_NAME) {
            Ok(fsimg.data_start())
        } else {
            Err(Error::Io(format!(
                "Failed to locate {} in ZIP file",
                &FS_IMG_NAME
            )))
        }
    }

    pub fn fsimg_size(&mut self) -> Result<u64, Error> {
        if let Ok(fsimg) = self.inner.by_name(&FS_IMG_NAME) {
            Ok(fsimg.size())
        } else {
            Err(Error::Io(format!(
                "Failed to locate {} in ZIP file",
                &FS_IMG_NAME
            )))
        }
    }

    pub fn verity_header(&mut self) -> Result<dm_verity::VerityHeader, Error> {
        let verity_offset = self.hashes()?.fs_verity_offset;
        if let Ok(mut fsimg) = self.inner.by_name(&FS_IMG_NAME) {
            io::copy(&mut fsimg.by_ref().take(verity_offset), &mut io::sink()).map_err(|e| {
                Error::Os {
                    context: format!("{} too small to extract verity header", &FS_IMG_NAME),
                    error: e,
                }
            })?;
            Ok(VerityHeader::from_bytes(fsimg.by_ref()).map_err(Error::Verity)?)
        } else {
            Err(Error::Io(format!(
                "Failed to locate {} in ZIP file",
                &FS_IMG_NAME
            )))
        }
    }

    pub fn file(&mut self, file: &Path) -> Result<impl std::io::Read + '_, Error> {
        if let Ok(zip_file) = self.inner.by_name(file.display().to_string().as_str()) {
            Ok(zip_file)
        } else {
            Err(Error::Io(format!(
                "Failed to locate {} in ZIP file",
                &file.display()
            )))
        }
    }

    pub fn into_inner(self) -> ZipArchive<R> {
        self.inner
    }
}

struct Builder {
    root: PathBuf,
    manifest: Manifest,
    key: Option<PathBuf>,
}

impl Builder {
    fn new(root: &Path, manifest: Manifest) -> Builder {
        Builder {
            root: PathBuf::from(root),
            manifest,
            key: Option::None,
        }
    }

    fn key(mut self, key: &Path) -> Builder {
        self.key = Some(key.to_path_buf());
        self
    }

    // TODO: If needed: add append method to include additional files to the npk

    fn build<W: Write + Seek>(&self, writer: W) -> Result<(), Error> {
        // Add manifest and root dir to tmp dir
        let tmp = tempfile::TempDir::new().map_err(|e| Error::Os {
            context: "Failed to create temporary directory".to_string(),
            error: e,
        })?;
        let tmp_root = copy_src_root_to_tmp(&self.root, &tmp)?;
        let tmp_manifest = write_manifest(&self.manifest, &tmp)?;

        // Create filesystem image
        let fsimg = tmp.path().join(&FS_IMG_BASE).with_extension(&FS_IMG_EXT);
        create_fs_img(&tmp_root, &self.manifest, &fsimg)?;

        // Create NPK
        if let Some(key) = &self.key {
            let signature = sign_npk(&key, &fsimg, &tmp_manifest)?;
            write_npk(writer, &self.manifest, &fsimg, Some(&signature))
        } else {
            write_npk(writer, &self.manifest, &fsimg, None)
        }
    }
}

/// Create an NPK for the northstar runtime.
/// sextant collects the artifacts in a given container directory, creates and signs the necessary metadata
/// and packs the results into a zipped NPK file.
///
/// # Example
///
/// To build the 'hello' example container:
///
/// sextant pack \
/// --dir examples/container/hello \
/// --out target/northstar/repository \
/// --key examples/keys/northstar.key \
pub fn pack(dir: &Path, out: &Path, key: Option<&Path>) -> Result<(), Error> {
    let manifest = read_manifest(dir)?;
    let name = manifest.name.clone();
    let version = manifest.version.clone();
    let mut builder = Builder::new(dir, manifest);
    if let Some(key) = key {
        builder = builder.key(key);
    }
    let npk_dest = out
        .join(format!("{}-{}.", &name, &version.to_string()))
        .with_extension(&NPK_EXT);
    let npk = File::create(&npk_dest).map_err(|e| Error::Os {
        context: format!("Failed to create NPK at '{}'", &npk_dest.display()),
        error: e,
    })?;
    builder.build(&npk)
}

pub fn unpack(npk: &Path, out: &Path) -> Result<(), Error> {
    let mut zip = open_zipped_npk(&npk)?;
    zip.extract(&out).map_err(|e| Error::Zip {
        context: format!("Failed to extract NPK to '{}'", &out.display()),
        error: e,
    })?;
    let fsimg = out.join(&FS_IMG_NAME);
    unpack_squashfs(&fsimg, &out)
}

/// Generate a keypair suitable for signing and verifying NPKs
pub fn gen_key(name: &str, out: &Path) -> Result<(), Error> {
    let mut csprng = OsRng {};
    let key_pair = Keypair::generate(&mut csprng);
    let pub_key = out.join(name).with_extension("pub");
    let prv_key = out.join(name).with_extension("key");
    assume_non_existing(&pub_key)?;
    assume_non_existing(&prv_key)?;

    fn write(data: &[u8], path: &Path) -> Result<(), Error> {
        let mut file = File::create(&path).map_err(|e| Error::Os {
            context: format!("Failed to create '{}'", &path.display()),
            error: e,
        })?;

        file.write_all(&data).map_err(|e| Error::Os {
            context: format!("Failed to write to '{}'", &path.display()),
            error: e,
        })?;
        Ok(())
    }
    write(&key_pair.public.to_bytes(), &pub_key)?;
    write(&key_pair.secret.to_bytes(), &prv_key)?;
    Ok(())
}

pub fn open_zipped_npk(npk: &Path) -> Result<ZipArchive<File>, Error> {
    let zip = zip::ZipArchive::new(File::open(&npk).map_err(|e| Error::Os {
        context: format!("Failed to open NPK at '{}'", &npk.display()),
        error: e,
    })?)
    .map_err(|e| Error::Zip {
        context: format!("Failed to parse ZIP format of NPK at '{}'", &npk.display()),
        error: e,
    })?;

    Ok(zip)
}

fn read_manifest(src: &Path) -> Result<Manifest, Error> {
    let manifest_path = src.join(MANIFEST_BASE).with_extension(&MANIFEST_EXT);
    let manifest_file = std::fs::File::open(&manifest_path).map_err(|e| Error::Os {
        context: format!("Failed to open manifest at '{}'", &manifest_path.display()),
        error: e,
    })?;
    let manifest = Manifest::from_reader(&manifest_file).map_err(|e| {
        Error::Manifest(format!(
            "Failed to parse '{}': {}",
            &manifest_path.display(),
            e
        ))
    })?;
    Ok(manifest)
}

fn write_manifest(manifest: &Manifest, tmp_dir: &TempDir) -> Result<PathBuf, Error> {
    let tmp_manifest_path = tmp_dir
        .path()
        .join(&MANIFEST_BASE)
        .with_extension(&MANIFEST_EXT);
    let tmp_manifest = File::create(&tmp_manifest_path).map_err(|e| Error::Os {
        context: format!("Failed to create '{}'", &tmp_manifest_path.display()),
        error: e,
    })?;
    manifest
        .to_writer(tmp_manifest)
        .map_err(|e| Error::Manifest(format!("Failed to serialize manifest: {}", e)))?;
    Ok(tmp_manifest_path)
}

fn read_keypair(key_file: &Path) -> Result<Keypair, Error> {
    let mut secret_key_bytes = [0u8; SECRET_KEY_LENGTH];
    File::open(&key_file)
        .map_err(|e| Error::Os {
            context: format!("Failed to open '{}'", &key_file.display()),
            error: e,
        })?
        .read_exact(&mut secret_key_bytes)
        .map_err(|e| Error::Os {
            context: format!("Failed to read key data from '{}'", &key_file.display()),
            error: e,
        })?;
    let secret_key = SecretKey::from_bytes(&secret_key_bytes).map_err(|e| Error::Key {
        context: format!("Failed to derive secret key from '{}'", &key_file.display()),
        error: e,
    })?;
    let public_key = PublicKey::from(&secret_key);
    Ok(Keypair {
        secret: secret_key,
        public: public_key,
    })
}

fn gen_hashes_yaml(
    tmp_manifest_path: &Path,
    fsimg_path: &Path,
    fsimg_size: u64,
    verity_hash: &[u8],
) -> Result<String, Error> {
    // Create hashes YAML
    let mut sha256 = Sha256::new();
    let mut tmp_manifest = File::open(&tmp_manifest_path).map_err(|e| Error::Os {
        context: format!("Failed to open '{}'", &tmp_manifest_path.display()),
        error: e,
    })?;
    io::copy(&mut tmp_manifest, &mut sha256)
        .map_err(|_e| Error::Manifest("Failed to calculate manifest checksum".to_string()))?;

    let manifest_hash = sha256.finalize();
    let mut sha256 = Sha256::new();
    let mut fsimg = File::open(&fsimg_path).map_err(|e| Error::Os {
        context: format!("Failed to open '{}'", &fsimg_path.display()),
        error: e,
    })?;
    io::copy(&mut fsimg, &mut sha256).map_err(|e| Error::Os {
        context: "Failed to read fs image".to_string(),
        error: e,
    })?;

    let fs_hash = sha256.finalize();
    let hashes = format!(
        "{}:\n  hash: {:02x?}\n\
         {}:\n  hash: {:02x?}\n  verity-hash: {:02x?}\n  verity-offset: {}\n",
        &MANIFEST_NAME,
        manifest_hash.iter().format(""),
        &FS_IMG_NAME,
        fs_hash.iter().format(""),
        verity_hash.iter().format(""),
        fsimg_size
    );
    Ok(hashes)
}

fn sign_npk(key_file: &Path, fsimg: &Path, tmp_manifest: &Path) -> Result<String, Error> {
    let fsimg_size = fs::metadata(&fsimg)
        .map_err(|e| Error::Os {
            context: format!("Fail to read read size of '{}'", &fsimg.display()),
            error: e,
        })?
        .len();
    let root_hash = append_dm_verity_block(&fsimg, fsimg_size).map_err(Error::Verity)?;
    let key_pair = read_keypair(&key_file)?;
    let hashes_yaml = gen_hashes_yaml(&tmp_manifest, &fsimg, fsimg_size, &root_hash)?;
    let signature_yaml = sign_hashes(&key_pair, &hashes_yaml);
    Ok(signature_yaml)
}

fn gen_pseudo_files(manifest: &Manifest) -> Vec<(String, u32)> {
    let mut pseudo_files: Vec<(String, u32)> = vec![];
    if manifest.init.is_some() {
        pseudo_files = vec![
            // The default is to have at least a minimal /dev mount
            ("/dev".to_string(), 444),
            ("/proc".to_string(), 444),
        ];
    }

    for (target, mount) in &manifest.mounts {
        match mount {
            Mount::Bind { flags, .. } => {
                let mode = if flags.contains(&MountFlag::Rw) {
                    777
                } else {
                    555
                };
                pseudo_files.push((target.display().to_string(), mode));
            }
            Mount::Persist => pseudo_files.push((target.display().to_string(), 777)),
            // /dev is default
            Mount::Dev { .. } => (),
            Mount::Resource { .. } => {
                // In order to support mount points with multiple path segments, we need to call mksquashfs multiple times:
                // e.g. to support res/foo in our image, we need to add /res/foo AND /res
                // ==> mksquashfs ... -p "/res/foo d 444 1000 1000"  -p "/res d 444 1000 1000" */
                let trail = path_trail(&target);
                for path in trail {
                    pseudo_files.push((path.display().to_string(), 555));
                }
            }
            Mount::Tmpfs { .. } => pseudo_files.push((target.display().to_string(), 777)),
        }
    }
    pseudo_files
}

fn sign_hashes(key_pair: &Keypair, hashes_yaml: &str) -> String {
    let signature = key_pair.sign(hashes_yaml.as_bytes());
    let signature_base64 = base64::encode(signature);
    let key_id = "northstar";
    let signature_yaml = format!(
        "{}---\nkey: {}\nsignature: {}",
        &hashes_yaml, &key_id, &signature_base64
    );
    signature_yaml
}

fn copy_src_root_to_tmp(src: &Path, tmp: &TempDir) -> Result<PathBuf, Error> {
    let src_root = src.join(&ROOT_DIR_NAME);
    let tmp_root = tmp.path().join(&ROOT_DIR_NAME);
    let options = fs_extra::dir::CopyOptions::new();
    if src_root.exists() {
        fs_extra::dir::copy(&src_root, &tmp, &options).map_err(|e| {
            Error::Io(format!(
                "Failed to copy from '{}' to '{}': {}",
                &src_root.display(),
                &tmp.path().display(),
                e
            ))
        })?;
    } else {
        // Create empty root dir at destination if we have nothing to copy
        fs_extra::dir::create(&tmp_root, false).map_err(|e| {
            Error::Io(format!(
                "Failed to create directory '{}': {}",
                &tmp_root.display(),
                e
            ))
        })?;
    }
    Ok(tmp_root)
}

fn create_fs_img(tmp_root: &Path, manifest: &Manifest, fsimg: &Path) -> Result<(), Error> {
    let pseudo_files = gen_pseudo_files(&manifest);
    create_squashfs(&tmp_root, &fsimg, &pseudo_files)
}

fn create_squashfs(out: &Path, src: &Path, pseudo_dirs: &[(String, u32)]) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    let compression_alg = "gzip";
    #[cfg(not(target_os = "linux"))]
    let compression_alg = "zstd";

    if which::which(&MKSQUASHFS_BIN).is_err() {
        return Err(Error::Squashfs(format!(
            "Failed to locate '{}'",
            &MKSQUASHFS_BIN
        )));
    }
    if !out.exists() {
        return Err(Error::Squashfs(format!(
            "Output directory '{}' does not exist",
            &out.display()
        )));
    }
    let mut cmd = Command::new(&MKSQUASHFS_BIN);
    cmd.arg(&out.display().to_string())
        .arg(&src.display().to_string())
        .arg("-all-root")
        .arg("-comp")
        .arg(compression_alg)
        .arg("-no-progress")
        .arg("-info");
    for dir in pseudo_dirs {
        cmd.arg("-p");
        cmd.arg(format!(
            "{} d {} {} {}",
            dir.0,
            dir.1.to_string(),
            PSEUDO_DIR_UID,
            PSEUDO_DIR_GID
        ));
    }
    cmd.output()
        .map_err(|e| Error::Squashfs(format!("Failed to execute '{}': {}", &MKSQUASHFS_BIN, e)))?;

    if !src.exists() {
        Err(Error::Squashfs(format!(
            "'{}' did not create '{}'",
            &MKSQUASHFS_BIN, &FS_IMG_NAME
        )))
    } else {
        Ok(())
    }
}

fn unpack_squashfs(image: &Path, out: &Path) -> Result<(), Error> {
    if which::which(&UNSQUASHFS_BIN).is_err() {
        return Err(Error::Squashfs(format!(
            "Failed to locate '{}'",
            &UNSQUASHFS_BIN
        )));
    }
    if !image.exists() {
        return Err(Error::Squashfs(format!(
            "Squashfs image at '{}' does not exist",
            &image.display()
        )));
    }
    let squashfs_root = out.join("squashfs-root");
    let mut cmd = Command::new(&UNSQUASHFS_BIN);
    cmd.arg("-dest")
        .arg(&squashfs_root.display().to_string())
        .arg(&image.display().to_string())
        .output()
        .map_err(|e| {
            Error::Squashfs(format!(
                "Error while executing '{}': {}",
                &UNSQUASHFS_BIN, e
            ))
        })?;
    Ok(())
}

fn write_npk<W: Write + Seek>(
    npk: W,
    manifest: &Manifest,
    fsimg: &Path,
    signature: Option<&str>,
) -> Result<(), Error> {
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let manifest_string = serde_yaml::to_string(&manifest)
        .map_err(|e| Error::Manifest(format!("Failed to serialize manifest: {}", e)))?;
    let mut zip = zip::ZipWriter::new(npk);
    zip.set_comment(format!(
        "{} {}",
        &NPK_VERSION_STR,
        &Manifest::VERSION.to_string()
    ));
    if let Some(signature) = signature {
        || -> Result<(), std::io::Error> {
            zip.start_file(SIGNATURE_NAME, options)?;
            zip.write_all(signature.as_bytes())
        }()
        .map_err(|e| Error::Os {
            context: "Failed to write signature to NPK".to_string(),
            error: e,
        })?;
    }

    zip.start_file(MANIFEST_NAME, options)
        .map_err(|e| Error::Zip {
            context: "Failed to write manifest to NPK".to_string(),
            error: e,
        })?;
    zip.write_all(manifest_string.as_bytes())
        .map_err(|e| Error::Os {
            context: "Failed to convert manifest to NPK".to_string(),
            error: e,
        })?;

    /* We need to ensure that the fs.img start at an offset of 4096 so we add empty (zeros) ZIP
     * 'extra data' to inflate the header of the ZIP file.
     * See chapter 4.3.6 of APPNOTE.TXT
     * (https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) */
    zip.start_file_aligned(FS_IMG_NAME, options, BLOCK_SIZE as u16)
        .map_err(|e| Error::Zip {
            context: "Could create aligned zip-file".to_string(),
            error: e,
        })?;
    let mut fsimg = File::open(&fsimg).map_err(|e| Error::Os {
        context: format!("Failed to open '{}'", &fsimg.display()),
        error: e,
    })?;

    io::copy(&mut fsimg, &mut zip).map_err(|e| Error::Os {
        context: "Failed to write the filesystem image to the archive".to_string(),
        error: e,
    })?;
    Ok(())
}

/// Return the list of sub-paths to the given directory except the root.
/// For example, the path '/res/dir/subdir' returns ('/res/dir/subdir', /res/dir/', '/res/').
fn path_trail(path: &Path) -> Vec<&Path> {
    let mut current_path = path;
    let mut ret = vec![];
    while let Some(parent_path) = current_path.parent() {
        ret.push(current_path);
        current_path = parent_path;
    }
    ret
}

fn assume_non_existing(path: &Path) -> Result<(), Error> {
    if path.exists() {
        Err(Error::Io(format!(
            "File '{}' already exists",
            &path.display()
        )))
    } else {
        Ok(())
    }
}
