use crate::{
    common::version::Version,
    npk::{
        dm_verity::{append_dm_verity_block, VerityHeader, BLOCK_SIZE},
        manifest::{
            mount::{Bind, Mount},
            Manifest,
        },
    },
};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as Base64, Engine as _};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use itertools::Itertools;
use rand_core::{OsRng, RngCore};
use semver::Comparator;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::io::{AsRawFd, RawFd},
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};
use tempfile::NamedTempFile;
use thiserror::Error;
use zip::ZipArchive;

use super::VERSION;

/// Default path to mksquashfs
pub const MKSQUASHFS: &str = "mksquashfs";
/// Default path to unsquashfs
pub const UNSQUASHFS: &str = "unsquashfs";

/// File system file name
pub const FS_IMG_NAME: &str = "fs.img";
/// Manifest file name
pub const MANIFEST_NAME: &str = "manifest.yaml";
/// Signature file name
pub const SIGNATURE_NAME: &str = "signature.yaml";
/// NPK extension
pub const NPK_EXT: &str = "npk";

/// Minimum mksquashfs major version supported
const MKSQUASHFS_MAJOR_VERSION_MIN: u64 = 4;
/// Minimum mksquashfs minor version supported
const MKSQUASHFS_MINOR_VERSION_MIN: u64 = 1;

type Zip<R> = ZipArchive<R>;

/// Npk loading Error
#[derive(Error, Debug)]
#[error(transparent)]
pub struct Error(#[from] anyhow::Error);

/// NPK archive comment
#[derive(Debug, Serialize, Deserialize)]
pub struct Meta {
    /// Version
    pub version: Version,
}

/// Squashfs Options
#[derive(Clone, Debug)]
pub struct SquashfsOptions {
    /// Path to mksquashfs executable
    pub mksquashfs: PathBuf,
    /// The compression algorithm used (default gzip)
    pub compression: Compression,
    /// Size of the blocks of data compressed separately
    pub block_size: Option<u32>,
}

impl Default for SquashfsOptions {
    fn default() -> Self {
        SquashfsOptions {
            compression: Compression::Gzip,
            block_size: None,
            mksquashfs: PathBuf::from(MKSQUASHFS),
        }
    }
}

/// NPK Hashes
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Hashes {
    /// Meta hash (zip comment)
    pub meta_hash: String,
    /// Hash of the manifest.yaml
    pub manifest_hash: String,
    /// Verity root hash
    pub fs_verity_hash: String,
    /// Offset of the verity block within the fs image
    pub fs_verity_offset: u64,
}

impl Hashes {
    /// Read hashes from `reader`.
    pub fn from_reader<R: Read>(mut reader: R) -> Result<Hashes, Error> {
        let mut buf = String::new();
        reader
            .read_to_string(&mut buf)
            .context("failed to read hashes")?;
        Hashes::from_str(&buf)
    }
}

impl FromStr for Hashes {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct MetaHash {
            hash: String,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct ManifestHash {
            hash: String,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct FsHash {
            verity_hash: String,
            verity_offset: u64,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct SerdeHashes {
            meta: MetaHash,
            #[serde(rename = "manifest.yaml")]
            manifest: ManifestHash,
            #[serde(rename = "fs.img")]
            fs: FsHash,
        }

        let hashes = serde_yaml::from_str::<SerdeHashes>(s).context("failed to parse hashes")?;

        Ok(Hashes {
            meta_hash: hashes.meta.hash,
            manifest_hash: hashes.manifest.hash,
            fs_verity_hash: hashes.fs.verity_hash,
            fs_verity_offset: hashes.fs.verity_offset,
        })
    }
}

/// Northstar package
#[derive(Debug)]
pub struct Npk<R> {
    meta: Meta,
    file: R,
    manifest: Manifest,
    fs_img_offset: u64,
    fs_img_size: u64,
    verity_header: Option<VerityHeader>,
    hashes: Option<Hashes>,
}

impl<R: Read + Seek> Npk<R> {
    /// Read a npk from `reader`
    pub fn from_reader(reader: R, key: Option<&VerifyingKey>) -> Result<Self, Error> {
        let mut zip = Zip::new(reader).context("archive error")?;

        // Check npk format version against `VERSION`.
        let version_request = semver::VersionReq {
            comparators: vec![Comparator {
                op: semver::Op::GreaterEq,
                major: VERSION.major,
                minor: Some(VERSION.minor),
                patch: None,
                pre: semver::Prerelease::default(),
            }],
        };

        // Read hashes from the npk if a key is passed
        let hashes = if let Some(key) = key {
            let hashes = hashes(&mut zip, key)?;
            Some(hashes)
        } else {
            None
        };

        let meta = meta(&zip, hashes.as_ref())?;
        let version = &meta.version;
        if !version_request.matches(&(version.into())) {
            return Err(anyhow!(
                "NPK version format {} doesn't match required version {}",
                meta.version,
                version_request
            )
            .into());
        }

        let manifest = manifest(&mut zip, hashes.as_ref())?;
        let (fs_img_offset, fs_img_size) = {
            let fs_img = &zip
                .by_name(FS_IMG_NAME)
                .with_context(|| format!("failed to locate {} in ZIP file", &FS_IMG_NAME))?;
            (fs_img.data_start(), fs_img.size())
        };

        let mut file = zip.into_inner();
        let verity_header = match &hashes {
            Some(hs) => {
                file.seek(SeekFrom::Start(fs_img_offset + hs.fs_verity_offset))
                    .with_context(|| {
                        format!("{} too small to extract verity header", &FS_IMG_NAME)
                    })?;
                Some(VerityHeader::from_bytes(&mut file).context("failed to read verity header")?)
            }
            None => None,
        };

        Ok(Self {
            meta,
            file,
            manifest,
            fs_img_offset,
            fs_img_size,
            verity_header,
            hashes,
        })
    }

    /// Load manifest from `npk`
    pub fn from_path(
        npk: &Path,
        key: Option<&VerifyingKey>,
    ) -> Result<Npk<BufReader<fs::File>>, Error> {
        let npk_file =
            fs::File::open(npk).with_context(|| format!("failed to open {}", npk.display()))?;
        Npk::from_reader(BufReader::new(npk_file), key)
    }

    /// Meta information
    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// Manifest
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Version
    pub fn version(&self) -> &Version {
        &self.meta.version
    }

    /// Offset of the fsimage within the npk
    pub fn fsimg_offset(&self) -> u64 {
        self.fs_img_offset
    }

    /// Size of the fsimage
    pub fn fsimg_size(&self) -> u64 {
        self.fs_img_size
    }

    /// Hashes
    pub fn hashes(&self) -> Option<&Hashes> {
        self.hashes.as_ref()
    }

    /// DM verity header
    pub fn verity_header(&self) -> Option<&VerityHeader> {
        self.verity_header.as_ref()
    }
}

impl AsRawFd for Npk<BufReader<fs::File>> {
    fn as_raw_fd(&self) -> RawFd {
        self.file.get_ref().as_raw_fd()
    }
}

fn meta<R: Read + Seek>(zip: &Zip<R>, hashes: Option<&Hashes>) -> Result<Meta> {
    let content = zip.comment();
    if let Some(Hashes { meta_hash, .. }) = &hashes {
        let expected_hash = hex::decode(meta_hash).context("failed to parse manifest hash")?;
        let actual_hash = Sha256::digest(content);
        if expected_hash != actual_hash.as_slice() {
            bail!(
                "invalid meta hash (expected={} actual={})",
                meta_hash,
                hex::encode(actual_hash)
            );
        }
    }
    serde_yaml::from_slice(zip.comment()).context("comment malformed")
}

fn hashes<R: Read + Seek>(zip: &mut Zip<R>, key: &VerifyingKey) -> Result<Hashes, Error> {
    // Read the signature file from the zip
    let signature_content = read_to_string(zip, SIGNATURE_NAME)?;

    // Split the two yaml components
    let mut documents = signature_content.split("---");
    let hashes_str = documents
        .next()
        .ok_or_else(|| anyhow!("malformed signatures file"))?;
    let hashes = Hashes::from_str(hashes_str)?;

    let signature = documents
        .next()
        .ok_or_else(|| anyhow!("malformed signatures file"))?;
    let signature = decode_signature(signature)?;

    key.verify_strict(hashes_str.as_bytes(), &signature)
        .context("invalid signature")?;

    Ok(hashes)
}

fn manifest<R: Read + Seek>(zip: &mut Zip<R>, hashes: Option<&Hashes>) -> Result<Manifest> {
    let content = read_to_string(zip, MANIFEST_NAME)?;
    if let Some(Hashes { manifest_hash, .. }) = &hashes {
        let expected_hash = hex::decode(manifest_hash).context("failed to parse manifest hash")?;
        let actual_hash = Sha256::digest(content.as_bytes());
        if expected_hash != actual_hash.as_slice() {
            bail!(
                "invalid manifest hash (expected={} actual={})",
                manifest_hash,
                hex::encode(actual_hash)
            );
        }
    }
    Manifest::from_str(&content).context("failed to parse manifest")
}

fn read_to_string<R: Read + Seek>(zip: &mut Zip<R>, name: &str) -> Result<String, Error> {
    let mut file = zip
        .by_name(name)
        .with_context(|| format!("failed to locate {name} in ZIP file"))?;
    let mut content = String::with_capacity(file.size() as usize);
    file.read_to_string(&mut content)
        .with_context(|| format!("failed to read from {name}"))?;
    Ok(content)
}

fn decode_signature(s: &str) -> Result<ed25519_dalek::Signature> {
    #[allow(unused)]
    #[derive(Debug, Deserialize)]
    struct SerdeSignature {
        signature: String,
    }

    let de: SerdeSignature = serde_yaml::from_str::<SerdeSignature>(s)
        .context("failed to parse signature YAML format")?;

    let signature = Base64
        .decode(de.signature)
        .context("failed to decode signature base 64 format")?;

    ed25519_dalek::Signature::from_slice(&signature)
        .context("failed to parse signature ed25519 format")
}

/// Squashfs compression algorithm
#[derive(Clone, Debug, Default)]
#[allow(missing_docs)]
pub enum Compression {
    None,
    #[default]
    Gzip,
    Lzo,
    Xz,
    Zstd,
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Compression::None => write!(f, "none"),
            Compression::Gzip => write!(f, "gzip"),
            Compression::Lzo => write!(f, "lzo"),
            Compression::Xz => write!(f, "xz"),
            Compression::Zstd => write!(f, "zstd"),
        }
    }
}

impl FromStr for Compression {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "gzip" => Ok(Compression::Gzip),
            "lzo" => Ok(Compression::Lzo),
            "xz" => Ok(Compression::Xz),
            "zstd" => Ok(Compression::Zstd),
            _ => Err(anyhow!("invalid compression algorithm").into()),
        }
    }
}

#[derive(Clone, Debug, Default)]
enum NpkBuilderManifest<'a> {
    #[default]
    None,
    Manifest(Manifest),
    ManifestPath(&'a Path),
}

/// Pack npks.
#[derive(Clone, Debug, Default)]
pub struct NpkBuilder<'a> {
    manifest: NpkBuilderManifest<'a>,
    root: Option<&'a Path>,
    fsimage: Option<&'a Path>,
    squashfs_options: Option<&'a SquashfsOptions>,
    key: Option<&'a Path>,
}

impl<'a> NpkBuilder<'a> {
    /// Set the manifest.
    pub fn manifest(mut self, manifest: &Manifest) -> NpkBuilder<'a> {
        self.manifest = NpkBuilderManifest::Manifest(manifest.clone());
        self
    }

    /// Set the manifest path.
    pub fn manifest_path(mut self, manifest: &'a Path) -> NpkBuilder<'a> {
        self.manifest = NpkBuilderManifest::ManifestPath(manifest);
        self
    }

    /// Set root directory.
    pub fn root(
        mut self,
        root: &'a Path,
        squashfs_options: Option<&'a SquashfsOptions>,
    ) -> NpkBuilder<'a> {
        self.root = Some(root);
        self.squashfs_options = squashfs_options;
        self
    }

    /// Use existing plain `fsimage` as file system image.
    pub fn fsimage(mut self, fsimage: &'a Path) -> NpkBuilder<'a> {
        self.fsimage = Some(fsimage);
        self
    }

    /// Use key for signing.
    pub fn key(mut self, key: &'a Path) -> NpkBuilder<'a> {
        self.key = Some(key);
        self
    }

    /// Write npk to `file`.
    pub fn to_file(self, file: &Path) -> Result<u64, Error> {
        let file = fs::File::create(file)
            .with_context(|| format!("failed to create {}", file.display()))?;
        self.to_writer(file)
    }

    /// Write npk to `dir` with the filename `{name}-{version}.npk` with the values
    /// from the manifest.
    pub fn to_dir(self, dir: &Path) -> Result<(PathBuf, u64), Error> {
        let mut me = self;
        // Append filename from manifest if only a directory path was given.
        // Otherwise use the given filename.
        if Path::is_dir(dir) {
            let manifest = me.get_manifest()?;
            let mut npk_path = dir.to_path_buf();
            npk_path.push(format!("{}-{}.", &manifest.name, &manifest.version));
            npk_path.set_extension(NPK_EXT);
            me.to_file(&npk_path)
                .map(|size| (npk_path.to_owned(), size))
        } else {
            Err(anyhow!("dir must be a directory").into())
        }
    }

    /// Write npk to `writer`.
    pub fn to_writer<W: Write + Seek>(self, writer: W) -> Result<u64, Error> {
        let mut me = self;

        const META: Meta = Meta { version: VERSION };
        let fsimage = me.fsimage;
        let root = me.root;
        let squashfs_options = me.squashfs_options.cloned().unwrap_or_default();
        let manifest = me.get_manifest()?;

        // Create zip.
        let options =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        let mut zip = zip::ZipWriter::new(writer);

        // Write meta data to zip comment.
        let meta_str = serde_yaml::to_string(&META).context("failed to serialize meta")?;
        zip.set_comment(meta_str);

        // Add manifest.
        let manifest_str = manifest.to_string();
        zip.start_file(MANIFEST_NAME, options)
            .context("failed to write manifest to NPK")?;
        zip.write_all(manifest_str.as_bytes())
            .context("failed to write manifest to NPK")?;

        let (fsimage, fsimage_size, fsimage_tmp) = match (root, fsimage) {
            (Some(_), Some(_)) => {
                return Err(anyhow!("root and fsimage are mutually exclusive")).map_err(Into::into);
            }
            (Some(root), None) => {
                // Create squashfs image.
                let fsimage =
                    tempfile::NamedTempFile::new().context("failed to create tempfile")?;
                let fsimage_size = mksquashfs(manifest, root, fsimage.path(), &squashfs_options)?;
                (fsimage.path().to_owned(), fsimage_size, Some(fsimage))
            }
            (None, Some(fsimage)) => {
                let fsimage_size = fs::metadata(fsimage)
                    .with_context(|| format!("failed to get metadata of {}", fsimage.display()))?
                    .len();
                (fsimage.to_path_buf(), fsimage_size, None)
            }
            (None, None) => return Err(anyhow!("missing root or fsimage")).map_err(Into::into),
        };

        let mut fsimage = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .open(fsimage)
            .context("failed to open fsimage")?;

        if let Some(key) = me.key {
            let signature = signature(key, &META, &mut fsimage, fsimage_size, &manifest_str)?;
            zip.start_file(SIGNATURE_NAME, options)
                .context("failed to add signature file")?;
            zip.write_all(signature.as_bytes())
                .context("failed to write signature to NPK")?;
        }

        // We need to ensure that the fs.img start at an offset of 4096 so we add empty (zeros) ZIP
        // 'extra data' to inflate the header of the ZIP file.
        // See chapter 4.3.6 of APPNOTE.TXT
        // (https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
        zip.start_file_aligned(FS_IMG_NAME, options, BLOCK_SIZE as u16)
            .context("failed to create aligned zip-file")?;
        fsimage
            .seek(SeekFrom::Start(0))
            .context("failed to seek to start of fs.img")?;
        io::copy(&mut fsimage, &mut zip)
            .context("failed to write the filesystem image to the archive")?;
        drop(fsimage_tmp);

        let mut zip = zip.finish().context("failed to flush zip")?;
        let zip_size = zip
            .seek(SeekFrom::End(0))
            .context("failed to seek to end of zip")?;

        Ok(zip_size)
    }

    fn get_manifest(&mut self) -> Result<&Manifest, Error> {
        match self.manifest {
            NpkBuilderManifest::None => Err(anyhow!("missing manifest").into()),
            NpkBuilderManifest::Manifest(ref manifest) => Ok(manifest),
            NpkBuilderManifest::ManifestPath(path) => {
                let file = fs::File::open(path)
                    .with_context(|| format!("failed to open {}", path.display()))?;
                let manifest = Manifest::from_reader(&file)
                    .with_context(|| format!("failed to parse {}", path.display()))?;
                self.manifest = NpkBuilderManifest::Manifest(manifest);
                self.get_manifest()
            }
        }
    }
}

/// Extract the npk content to `out`
pub fn unpack(npk: &Path, out: &Path) -> Result<(), Error> {
    unpack_with(npk, out, Path::new(UNSQUASHFS))
}

/// Extract the npk content to `out` with a give unsquashfs binary
pub fn unpack_with(path: &Path, out: &Path, unsquashfs: &Path) -> Result<(), Error> {
    // Open zip archive.
    let npk =
        fs::File::open(path).with_context(|| format!("failed to open {}", &path.display()))?;
    let mut zip = ZipArchive::new(BufReader::new(npk))
        .with_context(|| format!("failed to parse ZIP format: {}", &path.display()))?;

    // Extract zip archive.
    zip.extract(out)
        .with_context(|| format!("failed to extract NPK to {}", &out.display()))?;

    // Unpack squashfs image.
    let fsimg = out.join(FS_IMG_NAME);
    let root = out.join("root");

    let mut cmd = Command::new(unsquashfs);
    cmd.arg("-dest")
        .arg(&root.display().to_string())
        .arg(&fsimg.display().to_string());
    cmd.output().context("failed to unsquashfs")?;
    fs::remove_file(&fsimg).with_context(|| format!("failed to remove {}", &fsimg.display()))?;

    Ok(())
}

/// Generate a keypair suitable for signing and verifying NPKs
pub fn generate_key(name: &str, out: &Path) -> Result<(), Error> {
    fn assume_non_existing(path: &Path) -> anyhow::Result<()> {
        if path.exists() {
            bail!("file {} already exists", &path.display())
        } else {
            Ok(())
        }
    }

    let mut secret_key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_key_bytes);
    let secret_key = SigningKey::from_bytes(&secret_key_bytes);
    let public_key = ed25519_dalek::VerifyingKey::from(&secret_key);

    let secret_key_file = out.join(name).with_extension("key");
    let public_key_file = out.join(name).with_extension("pub");

    assume_non_existing(&public_key_file)?;
    assume_non_existing(&secret_key_file)?;

    fs::write(&secret_key_file, secret_key.to_bytes()).context("failed to write secret key")?;
    fs::write(&public_key_file, public_key.to_bytes()).context("failed to write public key")?;

    Ok(())
}

fn read_signing_key(key_file: &Path) -> Result<SigningKey, Error> {
    let mut secret_key_bytes = [0u8; SECRET_KEY_LENGTH];
    fs::File::open(key_file)
        .with_context(|| format!("failed to open '{}'", &key_file.display()))?
        .read_exact(&mut secret_key_bytes)
        .with_context(|| format!("failed to read key data from '{}'", &key_file.display()))?;

    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    Ok(signing_key)
}

/// Generate the signatures yaml file
fn hashes_yaml(
    meta_hash: &[u8],
    manifest_hash: &[u8],
    verity_hash: &[u8],
    verity_offset: u64,
) -> String {
    format!(
        "{}:\n  hash: {:02x?}\n\
         {}:\n  hash: {:02x?}\n\
         {}:\n  verity-hash: {:02x?}\n  verity-offset: {}\n",
        "meta",
        meta_hash.iter().format(""),
        &MANIFEST_NAME,
        manifest_hash.iter().format(""),
        &FS_IMG_NAME,
        verity_hash.iter().format(""),
        verity_offset
    )
}

/// Try to construct the signature yaml file
fn signature<I: Read + Write + Seek>(
    key: &Path,
    meta: &Meta,
    fsimg: I,
    fsimg_size: u64,
    manifest: &str,
) -> Result<String, Error> {
    let meta_hash =
        Sha256::digest(serde_yaml::to_string(&meta).context("failed to encode metadata")?);
    let manifest_hash = Sha256::digest(manifest.as_bytes());

    // Calculate verity root hash
    let fsimg_hash: &[u8] = &append_dm_verity_block(fsimg, fsimg_size)
        .context("failed to calculate verity root hash")?;

    // Format the signatures.yaml
    let hashes_yaml = hashes_yaml(&meta_hash, &manifest_hash, fsimg_hash, fsimg_size);

    let key = read_signing_key(key)?;
    let signature = key.sign(hashes_yaml.as_bytes());
    let signature_base64 = Base64.encode(signature.to_bytes());
    let signature_yaml = { format!("{}---\nsignature: {}", &hashes_yaml, &signature_base64) };

    Ok(signature_yaml)
}

/// Add pseudo files directives (directory) for `dir` to `w`.
fn pseudo_dir<W: io::Write>(w: &mut W, dir: &Path, mode: u16, uid: u16, gid: u16) -> Result<()> {
    // Each directory level needs to be passed to mksquashfs e.g:
    // /dev d 755 x x x
    // /dev/block d 755 x x x
    let mut p = PathBuf::from("/");
    for d in dir.iter().skip(1) {
        p.push(d);
        let dir = p.display();
        writeln!(w, "{dir} d {mode} {uid} {gid}")?;
    }
    Ok(())
}

/// Returns a temporary file with all the pseudo file definitions
fn write_pseudo_files<W: io::Write>(manifest: &Manifest, out: &mut W) -> Result<()> {
    let uid = manifest.uid;
    let gid = manifest.gid;

    // Create mountpoints as pseudofiles/dirs
    for (target, mount) in manifest.mounts.iter().sorted_by(|(a, _), (b, _)| a.cmp(b)) {
        match mount {
            Mount::Bind(Bind { options: flags, .. }) => {
                let mode = if flags.is_rw() { 755 } else { 555 };
                pseudo_dir(out, target.as_ref(), mode, uid, gid)?;
            }
            Mount::Persist => pseudo_dir(out, target.as_ref(), 755, uid, gid)?,
            Mount::Proc | Mount::Sysfs => pseudo_dir(out, target.as_ref(), 444, uid, gid)?,
            Mount::Resource { .. } => pseudo_dir(out, target.as_ref(), 555, uid, gid)?,
            Mount::Sockets => pseudo_dir(out, target.as_ref(), 755, uid, gid)?,
            Mount::Tmpfs { .. } => pseudo_dir(out, target.as_ref(), 755, uid, gid)?,
            Mount::Dev => {
                // Create a minimal set of chardevs:
                // └─ dev
                //     ├── fd -> /proc/self/fd
                //     ├── full
                //     ├── null
                //     ├── random
                //     ├── stderr -> /proc/self/fd/2
                //     ├── stdin -> /proc/self/fd/0
                //     ├── stdout -> /proc/self/fd/1
                //     ├── tty
                //     ├── urandom
                //     └── zero

                // Create /dev pseudo dir. This is needed in order to create pseudo chardev file in /dev
                pseudo_dir(out, target.as_ref(), 755, uid, gid)?;

                const XATTR_SECURITY_SELINUX: &str = "security.selinux";

                // Create chardevs with security context.
                for (dev, major, minor, security) in &[
                    ("full", 1, 7, "u:object_r:null_device:s0"),
                    ("null", 1, 3, "u:object_r:full_device:s0"),
                    ("random", 1, 8, "u:object_r:full_device:s0"),
                    ("tty", 5, 0, "u:object_r:owntty_device:s0"),
                    ("urandom", 1, 9, "u:object_r:random_device:s0"),
                    ("zero", 1, 5, "u:object_r:zero_device:s0"),
                ] {
                    let target: &Path = target.as_ref();
                    let target = target.join(dev).display().to_string();
                    writeln!(out, "{target} c 666 {uid} {gid} {major} {minor}",)?;
                    writeln!(out, "{target} x {XATTR_SECURITY_SELINUX}={security}",)?;
                }

                if manifest
                    .mounts
                    .iter()
                    .any(|m| matches!(m, (target, Mount::Proc {}) if target.as_str() == "/proc"))
                {
                    // Link fds
                    writeln!(out, "/proc/self/fd d 777 {uid} {gid}")?;
                    for (link, name, security) in &[
                        ("/proc/self/fd", "fd", "u:r:su:s0"),
                        ("/proc/self/fd/0", "stdin", "u:r:su:s0"),
                        ("/proc/self/fd/1", "stdout", "u:r:su:s0"),
                        ("/proc/self/fd/2", "stderr", "u:r:su:s0"),
                    ] {
                        let target: &Path = target.as_ref();
                        let target = target.join(name).display().to_string();
                        writeln!(out, "{target} s 777 {uid} {gid} {link}")?;

                        // Set security xattr if provided.
                        writeln!(out, "{target} x {XATTR_SECURITY_SELINUX}={security}",)?;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Run mksquashfs to create image.
fn mksquashfs(
    manifest: &Manifest,
    root: &Path,
    image: &Path,
    squashfs_opts: &SquashfsOptions,
) -> Result<u64> {
    let mksquashfs = &squashfs_opts.mksquashfs;

    // Check root
    if !root.exists() {
        bail!("root directory {} does not exist", &root.display());
    }

    // Check mksquashfs version
    let stdout = String::from_utf8(
        Command::new(mksquashfs)
            .arg("-version")
            .output()
            .with_context(|| format!("failed to execute '{}'", mksquashfs.display()))?
            .stdout,
    )
    .context("failed to parse mksquashfs output")?;
    let first_line = stdout.lines().next().unwrap_or_default();
    let mut major_minor = first_line.split(' ').nth(2).unwrap_or_default().split('.');
    let major = major_minor
        .next()
        .unwrap_or_default()
        .parse::<u64>()
        .unwrap_or_default();
    let minor = major_minor.next().unwrap_or_default();
    let minor = minor.parse::<u64>().unwrap_or_else(|_| {
        // Remove trailing subversion if present (e.g. 4.4-e0485802)
        minor
            .split(|c: char| !c.is_numeric())
            .next()
            .unwrap_or_default()
            .parse::<u64>()
            .unwrap_or_default()
    });
    let actual = Version::new(major, minor, 0);
    let required = Version::new(
        MKSQUASHFS_MAJOR_VERSION_MIN,
        MKSQUASHFS_MINOR_VERSION_MIN,
        0,
    );
    if actual < required {
        bail!(
            "Detected mksquashfs version {}.{} is too old. The required minimum version is {}.{}",
            major,
            minor,
            MKSQUASHFS_MAJOR_VERSION_MIN,
            MKSQUASHFS_MINOR_VERSION_MIN
        );
    }

    // Format pseudo files.
    let mut pseudo_files = NamedTempFile::new().context("failed to create temporary file")?;
    write_pseudo_files(manifest, &mut pseudo_files)?;

    // Run mksquashfs to create image
    let mut cmd = Command::new(mksquashfs);
    cmd.arg(&root.display().to_string())
        .arg(&image.display().to_string())
        .arg("-noappend")
        .arg("-no-progress")
        .arg("-info")
        .arg("-force-uid")
        .arg(manifest.uid.to_string())
        .arg("-force-gid")
        .arg(manifest.gid.to_string())
        .arg("-pf")
        .arg(pseudo_files.path());

    if let Some(block_size) = squashfs_opts.block_size {
        cmd.arg("-b").arg(format!("{block_size}"));
    }

    match &squashfs_opts.compression {
        Compression::None => {
            cmd.args(["-noI", "-noD", "-noF", "-noX", "-no-fragments"]);
        }
        compression => {
            cmd.arg("-comp").arg(compression.to_string());
        }
    }

    match cmd.output() {
        Ok(output) if !output.status.success() => {
            return Err(anyhow!("mksquashfs failed with {:?}", output.status))
        }
        Ok(_) => (),
        Err(e) => return Err(anyhow!("mksquashfs failed: {e}")),
    }

    let image_size = image
        .metadata()
        .context("failed to read image metadata")?
        .len();

    Ok(image_size)
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use crate::npk::npk::pseudo_dir;

    /// Test that the pseudo_dir function formats the output correctly.
    #[test]
    fn pseudo_dir_format() {
        let mut out = Vec::new();
        pseudo_dir(&mut out, Path::new("/dev/block"), 755, 0, 0).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "/dev d 755 0 0\n/dev/block d 755 0 0\n"
        )
    }

    /// Tests that the pseudo_dir function formats the output correctly when uid and gid are set.
    #[test]
    fn pseudo_dir_format_uid_gid() {
        let mut out = Vec::new();
        pseudo_dir(&mut out, Path::new("/dev"), 755, 20, 30).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "/dev d 755 20 30\n")
    }
}
