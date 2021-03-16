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
    fs, io,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    os::unix::io::{AsRawFd, RawFd},
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    task,
};
use zip::{result::ZipError, ZipArchive};

// Binaries
pub const MKSQUASHFS_BIN: &str = "mksquashfs";
pub const UNSQUASHFS_BIN: &str = "unsquashfs";

// First half of version string in ZIP comment
pub const NPK_VERSION_STR: &str = "npk_version:";

// File name and directory components
pub const FS_IMG_NAME: &str = "fs.img";
pub const MANIFEST_NAME: &str = "manifest.yaml";
pub const SIGNATURE_NAME: &str = "signature.yaml";
const FS_IMG_BASE: &str = "fs";
const FS_IMG_EXT: &str = "img";
const NPK_EXT: &str = "npk";

#[derive(Error, Debug)]
pub enum Error {
    #[error("Manifest error: {0}")]
    Manifest(String),
    #[error("IO error: {context}")]
    Io {
        context: String,
        #[source]
        error: std::io::Error,
    },
    #[error("IO error: {context}")]
    FsExtra {
        context: String,
        #[source]
        error: fs_extra::error::Error,
    },
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
    #[error("Key error: {context}")]
    Key {
        context: String,
        #[source]
        error: SignatureError,
    },
    #[error("Hashes malformed: {0}")]
    MalformedHashes(String),
    #[error("Signature malformed: {0}")]
    MalformedSignature(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Invalid compression algorithm")]
    InvalidCompressionAlgorithm,
}

#[derive(Clone, Eq, PartialEq, Debug)]
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

#[derive(Debug)]
pub struct Npk {
    file: std::fs::File,
    manifest: Manifest,
    version: Version,
    fs_img_offset: u64,
    fs_img_size: u64,
    verity_header: Option<dm_verity::VerityHeader>,
    hashes: Option<Hashes>,
}

fn extract_hashes(
    mut zip: &mut zip::ZipArchive<std::io::BufReader<std::fs::File>>,
    key: Option<&ed25519_dalek::PublicKey>,
) -> Result<Option<Hashes>, Error> {
    match key {
        Some(k) => {
            let signature_content = read_zip_file(&mut zip, SIGNATURE_NAME)?;
            let mut sections = signature_content.split("---");
            let hashes_string = sections.next().unwrap_or_default();

            let signature_string = sections.next().unwrap_or_default();
            let signature = decode_signature(signature_string)?;
            k.verify_strict(hashes_string.as_bytes(), &signature)
                .map_err(|_e| Error::InvalidSignature("Invalid signature".to_string()))?;

            Ok(Some(Hashes::from_str(hashes_string)?))
        }
        None => Ok(None),
    }
}

fn read_zip_file(
    zip: &mut zip::ZipArchive<std::io::BufReader<std::fs::File>>,
    name: &str,
) -> Result<String, Error> {
    let mut file = zip.by_name(name).map_err(|e| Error::Zip {
        context: format!("Failed to locate {} in ZIP file", name),
        error: e,
    })?;
    let mut content = String::with_capacity(file.size() as usize);
    file.read_to_string(&mut content).map_err(|e| Error::Io {
        context: format!("Failed to read from {}", name),
        error: e,
    })?;
    Ok(content)
}

fn decode_signature(s: &str) -> Result<ed25519_dalek::Signature, Error> {
    #[derive(Debug, Deserialize)]
    struct SerdeSignature {
        key: String,
        signature: String,
    }

    let de: SerdeSignature = serde_yaml::from_str::<SerdeSignature>(s).map_err(|e| {
        Error::MalformedSignature(format!("Failed to parse signature YAML format: {}", e))
    })?;

    let signature = base64::decode(de.signature).map_err(|e| {
        Error::MalformedSignature(format!("Failed to decode signature base 64 format: {}", e))
    })?;

    ed25519_dalek::Signature::from_bytes(&signature).map_err(|e| {
        Error::MalformedSignature(format!("Failed to parse signature ed25519 format: {}", e))
    })
}

impl Npk {
    pub async fn new(
        npk: tokio::fs::File,
        key: Option<&ed25519_dalek::PublicKey>,
    ) -> Result<Self, Error> {
        let npk = npk.into_std().await;
        task::block_in_place(|| {
            let mut archive =
                zip::ZipArchive::new(BufReader::new(npk)).map_err(|e| Error::Zip {
                    context: "Failed to parse ZIP format".to_string(),
                    error: e,
                })?;

            let version = {
                let comment = &std::str::from_utf8(&archive.comment()).map_err(|e| {
                    Error::Manifest(format!("Failed to read NPK version string {}", e))
                })?;
                let version = comment
                    .split_whitespace()
                    .tuples()
                    .find(|(k, _)| k == &NPK_VERSION_STR)
                    .map(|(_, v)| v)
                    .ok_or_else(|| Error::Manifest("Missing NPK version value".to_string()))?;

                Version::parse(&version)
                    .map_err(|e| Error::Manifest(format!("Failed to parse NPK version {}", e)))?
            };

            let hashes = extract_hashes(&mut archive, key)?;

            let manifest = {
                let content = read_zip_file(&mut archive, &MANIFEST_NAME)?;
                if let Some(Hashes { manifest_hash, .. }) = &hashes {
                    let expected_hash = hex::decode(manifest_hash).map_err(|e| {
                        Error::Manifest(format!("Failed to parse manifest hash {}", e))
                    })?;
                    let actual_hash = Sha256::digest(&content.as_bytes());
                    if expected_hash != actual_hash.as_slice() {
                        return Err(Error::Manifest(format!(
                            "Invalid manifest hash (expected={} actual={})",
                            manifest_hash,
                            hex::encode(actual_hash)
                        )));
                    }
                }
                Manifest::from_str(&content)
                    .map_err(|e| Error::Manifest(format!("Failed to parse manifest: {}", e)))?
            };

            let (fs_img_offset, fs_img_size) = {
                let fs_img = &archive.by_name(&FS_IMG_NAME).map_err(|e| Error::Zip {
                    context: format!("Failed to locate {} in ZIP file", &FS_IMG_NAME),
                    error: e,
                })?;
                (fs_img.data_start(), fs_img.size())
            };

            let mut reader = archive.into_inner();

            let verity_header = match &hashes {
                Some(hs) => {
                    reader
                        .seek(SeekFrom::Start(fs_img_offset + hs.fs_verity_offset))
                        .map_err(|e| Error::Io {
                            context: format!("{} too small to extract verity header", &FS_IMG_NAME),
                            error: e,
                        })?;
                    Some(VerityHeader::from_bytes(reader.by_ref()).map_err(Error::Verity)?)
                }
                None => None,
            };

            let file = reader.into_inner();

            Ok(Self {
                file,
                manifest,
                version,
                fs_img_offset,
                fs_img_size,
                verity_header,
                hashes,
            })
        })
    }

    pub async fn from_path(
        npk: &Path,
        key: Option<&ed25519_dalek::PublicKey>,
    ) -> Result<Self, Error> {
        return Npk::new(open_file(&npk).await?, key).await;
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn hashes(&self) -> Option<&Hashes> {
        self.hashes.as_ref()
    }

    pub fn fsimg_offset(&self) -> u64 {
        self.fs_img_offset
    }

    pub fn fsimg_size(&self) -> u64 {
        self.fs_img_size
    }

    pub fn verity_header(&self) -> Option<&dm_verity::VerityHeader> {
        self.verity_header.as_ref()
    }
}

impl AsRawFd for Npk {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

struct Builder {
    root: PathBuf,
    manifest: Manifest,
    key: Option<PathBuf>,
    squashfs_opts: SquashfsOpts,
}

impl Builder {
    fn new(root: &Path, manifest: Manifest) -> Builder {
        Builder {
            root: PathBuf::from(root),
            manifest,
            key: Option::None,
            squashfs_opts: SquashfsOpts::default(),
        }
    }

    fn key(mut self, key: &Path) -> Builder {
        self.key = Some(key.to_path_buf());
        self
    }

    fn squashfs_opts(mut self, opts: SquashfsOpts) -> Builder {
        self.squashfs_opts = opts;
        self
    }

    async fn build<W: Write + Seek>(&self, writer: W) -> Result<(), Error> {
        // Create squashfs image
        let tmp = tempfile::TempDir::new().map_err(|e| Error::Io {
            context: "Failed to create temporary directory".to_string(),
            error: e,
        })?;
        let fsimg = tmp.path().join(&FS_IMG_BASE).with_extension(&FS_IMG_EXT);
        create_squashfs_img(&self.manifest, &self.root, &fsimg, &self.squashfs_opts).await?;

        // Sign and write NPK
        if let Some(key) = &self.key {
            let signature = sign_npk(&key, &fsimg, &self.manifest).await?;
            write_npk(writer, &self.manifest, &fsimg, Some(&signature)).await
        } else {
            write_npk(writer, &self.manifest, &fsimg, None).await
        }
    }
}

#[derive(Debug)]
pub enum CompressionAlgorithm {
    Gzip,
    Lzma,
    Lzo,
    Xz,
    Zstd,
}

impl std::fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressionAlgorithm::Gzip => write!(f, "gzip"),
            CompressionAlgorithm::Lzma => write!(f, "lzma"),
            CompressionAlgorithm::Lzo => write!(f, "lzo"),
            CompressionAlgorithm::Xz => write!(f, "xz"),
            CompressionAlgorithm::Zstd => write!(f, "zstd"),
        }
    }
}

impl FromStr for CompressionAlgorithm {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "gzip" => Ok(CompressionAlgorithm::Gzip),
            "lzma" => Ok(CompressionAlgorithm::Lzma),
            "lzo" => Ok(CompressionAlgorithm::Lzo),
            "xz" => Ok(CompressionAlgorithm::Xz),
            "zstd" => Ok(CompressionAlgorithm::Zstd),
            _ => Err(Error::InvalidCompressionAlgorithm),
        }
    }
}

/// Squashfs Options
#[derive(Debug, Default)]
pub struct SquashfsOpts {
    /// The compression algorithm used (default gzip)
    pub comp: Option<CompressionAlgorithm>,
    /// Size of the blocks of data compressed separately
    pub block_size: Option<u32>,
}

/// Create an NPK for the northstar runtime.
/// sextant collects the artifacts in a given container directory, creates and signs the necessary metadata
/// and packs the results into a zipped NPK file.
///
/// # Arguments
/// * `manifest` - Path to the container's manifest file
/// * `root` - Path to the container's root directory
/// * `out` - Directory where the resulting NPK will be written to
/// * `key` - Path to the key used to sign the package
///
/// # Example
///
/// To build the 'hello' example container:
///
/// sextant pack \
/// --manifest examples/container/hello/manifest.yaml \
/// --root examples/container/hello/root \
/// --out target/northstar/repository \
/// --key examples/keys/northstar.key \
pub async fn pack(
    manifest: &Path,
    root: &Path,
    out: &Path,
    key: Option<&Path>,
) -> Result<(), Error> {
    pack_with(manifest, root, out, key, SquashfsOpts::default()).await
}

/// Create an NPK with special `squashfs` options
/// sextant collects the artifacts in a given container directory, creates and signs the necessary metadata
/// and packs the results into a zipped NPK file.
///
/// # Arguments
/// * `manifest` - Path to the container's manifest file
/// * `root` - Path to the container's root directory
/// * `out` - Directory where the resulting NPK will be written to
/// * `key` - Path to the key used to sign the package
/// * `squashfs_opts` - Options for `mksquashfs`
///
/// # Example
///
/// To build the 'hello' example container:
///
/// sextant pack \
/// --manifest examples/container/hello/manifest.yaml \
/// --root examples/container/hello/root \
/// --out target/northstar/repository \
/// --key examples/keys/northstar.key \
/// --comp xz \
/// --block-size 65536 \
pub async fn pack_with(
    manifest: &Path,
    root: &Path,
    out: &Path,
    key: Option<&Path>,
    squashfs_opts: SquashfsOpts,
) -> Result<(), Error> {
    let manifest = read_manifest(manifest).await?;
    let name = manifest.name.clone();
    let version = manifest.version.clone();
    let mut builder = Builder::new(root, manifest);
    if let Some(key) = key {
        builder = builder.key(&key);
    }
    builder = builder.squashfs_opts(squashfs_opts);

    let npk_dest = out
        .join(format!("{}-{}.", &name, &version.to_string()))
        .with_extension(&NPK_EXT);
    let npk = File::create(&npk_dest).await.map_err(|e| Error::Io {
        context: format!("Failed to create NPK: '{}'", &npk_dest.display()),
        error: e,
    })?;
    builder.build(npk.into_std().await).await
}

pub async fn unpack(npk: &Path, out: &Path) -> Result<(), Error> {
    let mut zip = open_zip(&npk).await?;
    task::block_in_place(|| zip.extract(&out)).map_err(|e| Error::Zip {
        context: format!("Failed to extract NPK to '{}'", &out.display()),
        error: e,
    })?;
    let fsimg = out.join(&FS_IMG_NAME);
    unpack_squashfs(&fsimg, &out).await
}

/// Generate a keypair suitable for signing and verifying NPKs
pub async fn gen_key(name: &str, out: &Path) -> Result<(), Error> {
    fn assume_non_existing(path: &Path) -> Result<(), Error> {
        if path.exists() {
            Err(Error::Io {
                context: format!("File '{}' already exists", &path.display()),
                error: io::ErrorKind::NotFound.into(),
            })
        } else {
            Ok(())
        }
    }

    async fn write(data: &[u8], path: &Path) -> Result<(), Error> {
        let mut file = File::create(&path).await.map_err(|e| Error::Io {
            context: format!("Failed to create '{}'", &path.display()),
            error: e,
        })?;
        file.write_all(&data).await.map_err(|e| Error::Io {
            context: format!("Failed to write to '{}'", &path.display()),
            error: e,
        })?;
        Ok(())
    }

    let mut csprng = OsRng {};
    let key_pair = Keypair::generate(&mut csprng);
    let pub_key = out.join(name).with_extension("pub");
    let prv_key = out.join(name).with_extension("key");
    assume_non_existing(&pub_key)?;
    assume_non_existing(&prv_key)?;
    write(&key_pair.public.to_bytes(), &pub_key).await?;
    write(&key_pair.secret.to_bytes(), &prv_key).await?;
    Ok(())
}

async fn read_manifest(path: &Path) -> Result<Manifest, Error> {
    let file = open_file(&path).await?.into_std().await;
    let manifest = task::block_in_place(|| Manifest::from_reader(&file))
        .map_err(|e| Error::Manifest(format!("Failed to parse '{}': {}", &path.display(), e)))?;
    Ok(manifest)
}

async fn read_keypair(key_file: &Path) -> Result<Keypair, Error> {
    let mut secret_key_bytes = [0u8; SECRET_KEY_LENGTH];
    open_file(&key_file)
        .await?
        .read_exact(&mut secret_key_bytes)
        .await
        .map_err(|e| Error::Io {
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

async fn gen_hashes_yaml(
    manifest: &Manifest,
    fsimg: &Path,
    fsimg_size: u64,
    verity_hash: &[u8],
) -> Result<String, Error> {
    // Create hashes YAML
    let mut sha256 = Sha256::new();
    sha2::digest::Update::update(&mut sha256, manifest.to_string().as_bytes());
    let manifest_hash = sha256.finalize();
    let mut sha256 = Sha256::new();
    let mut fsimg = open_file(&fsimg).await?.into_std().await;
    task::block_in_place(|| io::copy(&mut fsimg, &mut sha256)).map_err(|e| Error::Io {
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

async fn sign_npk(key: &Path, fsimg: &Path, manifest: &Manifest) -> Result<String, Error> {
    let fsimg_size = task::block_in_place(|| fs::metadata(&fsimg))
        .map_err(|e| Error::Io {
            context: format!("Failed to read file size: '{}'", &fsimg.display()),
            error: e,
        })?
        .len();
    let root_hash = append_dm_verity_block(fsimg, fsimg_size)
        .await
        .map_err(Error::Verity)?;
    let key_pair = read_keypair(&key).await?;
    let hashes_yaml = gen_hashes_yaml(&manifest, &fsimg, fsimg_size, &root_hash).await?;
    let signature_yaml = sign_hashes(&key_pair, &hashes_yaml).await;
    Ok(signature_yaml)
}

/// Returns a temporary file with all the pseudo file definitions
async fn gen_pseudo_files(manifest: &Manifest) -> Result<NamedTempFile, Error> {
    let pseudo_file_entries = task::block_in_place(|| {
        NamedTempFile::new().map_err(|e| Error::Io {
            context: "Failed to create temporary file".to_string(),
            error: e,
        })
    })?;
    let file = pseudo_file_entries.as_file();
    let uid = manifest.uid;
    let gid = manifest.gid;

    async fn add_directory(
        mut file: &std::fs::File,
        directory: &Path,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<(), Error> {
        task::block_in_place(|| {
            writeln!(file, "{} d {} {} {}", directory.display(), mode, uid, gid)
        })
        .map_err(|e| Error::Io {
            context: format!("Failed to write entry {} to temp file", directory.display()),
            error: e,
        })
    }

    if manifest.init.is_some() {
        // The default is to have at least a minimal /dev mount
        add_directory(&file, Path::new("/dev"), 444, uid, gid).await?;
        add_directory(&file, Path::new("/proc"), 444, uid, gid).await?;
    }

    for (target, mount) in &manifest.mounts {
        let mode = match mount {
            Mount::Bind { flags, .. } => {
                if flags.contains(&MountFlag::Rw) {
                    777
                } else {
                    555
                }
            }
            Mount::Persist => 777,
            Mount::Resource { .. } => 555,
            Mount::Tmpfs { .. } => 777,
            // /dev is default
            Mount::Dev { .. } => continue,
        };

        // In order to support mount points with multiple path segments, we need to call mksquashfs multiple times:
        // e.g. to support res/foo in our image, we need to add /res/foo AND /res
        // ==> mksquashfs ... -p "/res/foo d 444 1000 1000"  -p "/res d 444 1000 1000" */
        let mut subdir = PathBuf::from("/");
        for dir in target.iter().skip(1) {
            subdir.push(dir);
            add_directory(file, &subdir, mode, uid, gid).await?;
        }
    }

    Ok(pseudo_file_entries)
}

async fn sign_hashes(key_pair: &Keypair, hashes_yaml: &str) -> String {
    let signature = task::block_in_place(|| key_pair.sign(hashes_yaml.as_bytes()));
    let signature_base64 = base64::encode(signature);
    let key_id = "northstar";
    let signature_yaml = format!(
        "{}---\nkey: {}\nsignature: {}",
        &hashes_yaml, &key_id, &signature_base64
    );
    signature_yaml
}

async fn create_squashfs_img(
    manifest: &Manifest,
    root: &Path,
    image: &Path,
    squashfs_opts: &SquashfsOpts,
) -> Result<(), Error> {
    let pseudo_files = gen_pseudo_files(&manifest).await?;

    task::block_in_place(|| {
        which::which(&MKSQUASHFS_BIN)
            .map_err(|_| Error::Squashfs(format!("Failed to locate '{}'", &MKSQUASHFS_BIN)))
    })?;
    if !root.exists() {
        return Err(Error::Squashfs(format!(
            "Root directory '{}' does not exist",
            &root.display()
        )));
    }

    let compression_algorithm = squashfs_opts
        .comp
        .as_ref()
        .unwrap_or(&CompressionAlgorithm::Gzip);
    let mut cmd = Command::new(&MKSQUASHFS_BIN);
    cmd.arg(&root.display().to_string())
        .arg(&image.display().to_string())
        .arg("-no-progress")
        .arg("-comp")
        .arg(compression_algorithm.to_string())
        .arg("-info")
        .arg("-force-uid")
        .arg(manifest.uid.to_string())
        .arg("-force-gid")
        .arg(manifest.gid.to_string())
        .arg("-pf")
        .arg(pseudo_files.path());
    if let Some(block_size) = squashfs_opts.block_size {
        cmd.arg("-b").arg(format!("{}", block_size));
    }
    task::block_in_place(|| -> Result<(), Error> {
        cmd.output().map_err(|e| {
            Error::Squashfs(format!("Failed to execute '{}': {}", &MKSQUASHFS_BIN, e))
        })?;
        if !image.exists() {
            return Err(Error::Squashfs(format!(
                "'{}' failed to create '{}'",
                &MKSQUASHFS_BIN,
                &image.display()
            )));
        }
        Ok(())
    })?;
    Ok(())
}

async fn unpack_squashfs(image: &Path, out: &Path) -> Result<(), Error> {
    let squashfs_root = out.join("squashfs-root");

    task::block_in_place(|| {
        which::which(&UNSQUASHFS_BIN)
            .map_err(|_| Error::Squashfs(format!("Failed to locate '{}'", &UNSQUASHFS_BIN)))
    })?;
    if !image.exists() {
        return Err(Error::Squashfs(format!(
            "Squashfs image '{}' does not exist",
            &image.display()
        )));
    }
    let mut cmd = Command::new(&UNSQUASHFS_BIN);
    cmd.arg("-dest")
        .arg(&squashfs_root.display().to_string())
        .arg(&image.display().to_string());
    task::block_in_place(|| {
        cmd.output().map_err(|e| {
            Error::Squashfs(format!(
                "Error while executing '{}': {}",
                &UNSQUASHFS_BIN, e
            ))
        })
    })?;
    Ok(())
}

async fn write_npk<W: Write + Seek>(
    npk: W,
    manifest: &Manifest,
    fsimg: &Path,
    signature: Option<&str>,
) -> Result<(), Error> {
    let mut fsimg = open_file(&fsimg).await?.into_std().await;
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let manifest_string = serde_yaml::to_string(&manifest)
        .map_err(|e| Error::Manifest(format!("Failed to serialize manifest: {}", e)))?;

    task::block_in_place(|| -> Result<(), Error> {
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
            .map_err(|e| Error::Io {
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
            .map_err(|e| Error::Io {
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
        io::copy(&mut fsimg, &mut zip).map_err(|e| Error::Io {
            context: "Failed to write the filesystem image to the archive".to_string(),
            error: e,
        })?;
        Ok(())
    })?;

    Ok(())
}

pub async fn open_zip(file: &Path) -> Result<ZipArchive<std::fs::File>, Error> {
    let open_file = open_file(&file).await?.into_std().await;
    let zip = task::block_in_place(|| zip::ZipArchive::new(open_file)).map_err(|e| Error::Zip {
        context: format!("Failed to parse ZIP format: '{}'", &file.display()),
        error: e,
    })?;
    Ok(zip)
}

async fn open_file(path: &Path) -> Result<tokio::fs::File, Error> {
    Ok(File::open(&path).await.map_err(|e| Error::Io {
        context: format!("Failed to open '{}'", &path.display()),
        error: e,
    })?)
}
