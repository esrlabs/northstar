use crate::{
    common::version::Version,
    npk::{
        dm_verity::{append_dm_verity_block, VerityHeader, BLOCK_SIZE},
        manifest::{
            mount::{Bind, Mount, MountOption},
            Manifest,
        },
    },
};
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer, SECRET_KEY_LENGTH};
use itertools::Itertools;
use rand_core::{OsRng, RngCore};
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
use zeroize::Zeroize;
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

/// NPK Hashes
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Hashes {
    /// Hash of the manifest.yaml
    pub manifest_hash: String,
    /// Verity root hash
    pub fs_verity_hash: String,
    /// Offset of the verity block within the fs image
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
        struct FsHash {
            verity_hash: String,
            verity_offset: u64,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct SerdeHashes {
            #[serde(rename = "manifest.yaml")]
            manifest: ManifestHash,
            #[serde(rename = "fs.img")]
            fs: FsHash,
        }

        let hashes = serde_yaml::from_str::<SerdeHashes>(s).context("failed to parse hashes")?;

        Ok(Hashes {
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
    pub fn from_reader(reader: R, key: Option<&PublicKey>) -> Result<Self, Error> {
        let mut zip = Zip::new(reader).context("archive error")?;

        let meta = meta(&zip)?;
        if meta.version != VERSION {
            return Err(anyhow!("version mismatch {} vs {}", meta.version, VERSION).into());
        }

        // Read hashes from the npk if a key is passed
        let hashes = if let Some(key) = key {
            let hashes = hashes(&mut zip, key)?;
            Some(hashes)
        } else {
            None
        };

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
        key: Option<&PublicKey>,
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

fn meta<R: Read + Seek>(zip: &Zip<R>) -> Result<Meta> {
    serde_yaml::from_slice(zip.comment()).context("comment malformed")
}

fn hashes<R: Read + Seek>(zip: &mut Zip<R>, key: &PublicKey) -> Result<Hashes, Error> {
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
        .with_context(|| format!("failed to locate {} in ZIP file", name))?;
    let mut content = String::with_capacity(file.size() as usize);
    file.read_to_string(&mut content)
        .with_context(|| format!("failed to read from {}", name))?;
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

    let signature =
        base64::decode(de.signature).context("failed to decode signature base 64 format")?;

    ed25519_dalek::Signature::from_bytes(&signature)
        .context("failed to parse signature ed25519 format")
}

struct Builder {
    root: PathBuf,
    manifest: Manifest,
    key: Option<PathBuf>,
    squashfs_options: SquashfsOptions,
}

impl Builder {
    fn new(root: &Path, manifest: Manifest) -> Builder {
        Builder {
            root: PathBuf::from(root),
            manifest,
            key: None,
            squashfs_options: SquashfsOptions::default(),
        }
    }

    fn key(mut self, key: &Path) -> Builder {
        self.key = Some(key.to_path_buf());
        self
    }

    fn squashfs_opts(mut self, opts: SquashfsOptions) -> Builder {
        self.squashfs_options = opts;
        self
    }

    fn build<W: Write + Seek>(&self, writer: W) -> Result<()> {
        // Create squashfs image
        let tmp = tempfile::TempDir::new().context("failed to create temporary directory")?;
        let fsimg = tmp.path().join(FS_IMG_NAME);
        create_squashfs_img(&self.manifest, &self.root, &fsimg, &self.squashfs_options)?;

        // Sign and write NPK
        if let Some(key) = &self.key {
            let signature = signature(key, &fsimg, &self.manifest)?;
            write_npk(writer, &self.manifest, &fsimg, Some(&signature))
        } else {
            write_npk(writer, &self.manifest, &fsimg, None)
        }
    }
}

/// Squashfs compression algorithm
#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub enum CompressionAlgorithm {
    Gzip,
    Lzma,
    Lzo,
    Xz,
    Zstd,
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            _ => Err(anyhow!("invalid compression algorithm").into()),
        }
    }
}

/// Squashfs Options
#[derive(Clone, Debug)]
pub struct SquashfsOptions {
    /// Path to mksquashfs executable
    pub mksquashfs: PathBuf,
    /// The compression algorithm used (default gzip)
    pub compression_algorithm: CompressionAlgorithm,
    /// Size of the blocks of data compressed separately
    pub block_size: Option<u32>,
}

impl Default for SquashfsOptions {
    fn default() -> Self {
        SquashfsOptions {
            compression_algorithm: CompressionAlgorithm::Gzip,
            block_size: None,
            mksquashfs: PathBuf::from(MKSQUASHFS),
        }
    }
}

/// Create an NPK for the northstar runtime.
/// northstar-sextant collects the artifacts in a given container directory, creates and signs the necessary metadata
/// and packs the results into a zipped NPK file.
///
/// # Arguments
/// * `manifest` - Path to the container's manifest file
/// * `root` - Path to the container's root directory
/// * `out` - Target directory or filename of the packed NPK
/// * `key` - Path to the key used to sign the package
///
/// # Example
///
/// To build the 'hello' example container:
///
/// northstar-sextant pack \
/// --manifest examples/hello/manifest.yaml \
/// --root examples/hello/root \
/// --out target/northstar/repository \
/// --key examples/keys/northstar.key \
pub fn pack(manifest: &Path, root: &Path, out: &Path, key: Option<&Path>) -> Result<(), Error> {
    pack_with(manifest, root, out, key, SquashfsOptions::default())
}

/// Create an NPK with special `squashfs` options
/// northstar-sextant collects the artifacts in a given container directory, creates and signs the necessary metadata
/// and packs the results into a zipped NPK file.
///
/// # Arguments
/// * `manifest` - Path to the container's manifest file
/// * `root` - Path to the container's root directory
/// * `out` - Target directory or filename of the packed NPK
/// * `key` - Path to the key used to sign the package
/// * `squashfs_opts` - Options for `mksquashfs`
///
/// # Example
///
/// To build the 'hello' example container:
///
/// northstar-sextant pack \
/// --manifest examples/hello/manifest.yaml \
/// --root examples/hello/root \
/// --out target/northstar/repository \
/// --key examples/keys/northstar.key \
/// --comp xz \
/// --block-size 65536 \
pub fn pack_with(
    manifest: &Path,
    root: &Path,
    out: &Path,
    key: Option<&Path>,
    squashfs_opts: SquashfsOptions,
) -> Result<(), Error> {
    let manifest = read_manifest(manifest)?;
    let name = manifest.name.clone();
    let version = manifest.version.clone();
    let mut builder = Builder::new(root, manifest);
    if let Some(key) = key {
        builder = builder.key(key);
    }
    builder = builder.squashfs_opts(squashfs_opts);

    let mut dest = out.to_path_buf();
    // Append filename from manifest if only a directory path was given
    if Path::is_dir(out) {
        dest.push(format!("{}-{}.", &name, &version));
        dest.set_extension(&NPK_EXT);
    }
    let npk = fs::File::create(&dest)
        .with_context(|| format!("failed to create NPK: '{}'", &dest.display()))?;
    builder.build(npk)?;
    Ok(())
}

/// Extract the npk content to `out`
pub fn unpack(npk: &Path, out: &Path) -> Result<(), Error> {
    unpack_with(npk, out, Path::new(UNSQUASHFS))
}

/// Extract the npk content to `out` with a give unsquashfs binary
pub fn unpack_with(npk: &Path, out: &Path, unsquashfs: &Path) -> Result<(), Error> {
    let mut zip = open(npk)?;
    zip.extract(&out)
        .with_context(|| format!("failed to extract NPK to '{}'", &out.display()))?;
    let fsimg = out.join(&FS_IMG_NAME);
    unpack_squashfs(&fsimg, out, unsquashfs)?;
    Ok(())
}

/// Generate a keypair suitable for signing and verifying NPKs
pub fn generate_key(name: &str, out: &Path) -> Result<(), Error> {
    fn assume_non_existing(path: &Path) -> anyhow::Result<()> {
        if path.exists() {
            bail!("file '{}' already exists", &path.display())
        } else {
            Ok(())
        }
    }

    fn write(data: &[u8], path: &Path) -> Result<(), Error> {
        let mut file = fs::File::create(&path)
            .with_context(|| format!("failed to create '{}'", path.display()))?;
        file.write_all(data)
            .with_context(|| format!("failed to write to '{}'", &path.display()))?;
        Ok(())
    }

    let mut secret_key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_key_bytes);

    let secret_key = secret_key(secret_key_bytes)?;
    let public_key = ed25519_dalek::PublicKey::from(&secret_key);

    let secret_key_file = out.join(name).with_extension("key");
    let public_key_file = out.join(name).with_extension("pub");

    assume_non_existing(&public_key_file)?;
    assume_non_existing(&secret_key_file)?;

    write(&secret_key.to_bytes(), &secret_key_file)?;
    write(&public_key.to_bytes(), &public_key_file)?;

    Ok(())
}

fn read_manifest(path: &Path) -> Result<Manifest> {
    let file =
        fs::File::open(&path).with_context(|| format!("failed to open '{}'", &path.display()))?;
    Manifest::from_reader(&file).with_context(|| format!("failed to parse '{}'", &path.display()))
}

fn read_keypair(key_file: &Path) -> Result<Keypair, Error> {
    let mut secret_key_bytes = [0u8; SECRET_KEY_LENGTH];
    fs::File::open(&key_file)
        .with_context(|| format!("failed to open '{}'", &key_file.display()))?
        .read_exact(&mut secret_key_bytes)
        .with_context(|| format!("failed to read key data from '{}'", &key_file.display()))?;

    let secret_key = secret_key(secret_key_bytes)?;
    let public_key = PublicKey::from(&secret_key);

    Ok(Keypair {
        secret: secret_key,
        public: public_key,
    })
}

/// Derive an Ed25519 SecretKey. The provided data is zeroized afterwards.
fn secret_key(mut bytes: [u8; SECRET_KEY_LENGTH]) -> Result<SecretKey> {
    let secret_key =
        SecretKey::from_bytes(bytes.as_slice()).context("failed to read secret key")?;
    bytes.zeroize(); // Destroy original private key material
    Ok(secret_key)
}

/// Generate the signatures yaml file
fn hashes_yaml(manifest_hash: &[u8], verity_hash: &[u8], verity_offset: u64) -> String {
    format!(
        "{}:\n  hash: {:02x?}\n\
         {}:\n  verity-hash: {:02x?}\n  verity-offset: {}\n",
        &MANIFEST_NAME,
        manifest_hash.iter().format(""),
        &FS_IMG_NAME,
        verity_hash.iter().format(""),
        verity_offset
    )
}

/// Try to construct the signature yaml file
fn signature(key: &Path, fsimg: &Path, manifest: &Manifest) -> Result<String, Error> {
    let manifest_hash = {
        let mut sha256 = Sha256::new();
        sha2::digest::Update::update(&mut sha256, manifest.to_string().as_bytes());
        sha256.finalize()
    };

    // The size of the fs image is the offset of the verity block. The verity block
    // is appended to the fs.img
    let fsimg_size = fs::metadata(&fsimg)
        .with_context(|| format!("failed to read file size: '{}'", &fsimg.display()))?
        .len();
    // Calculate verity root hash
    let fsimg_hash: &[u8] = &append_dm_verity_block(fsimg, fsimg_size)
        .context("failed to calculate verity root hash")?;

    // Format the signatures.yaml
    let hashes_yaml = hashes_yaml(&manifest_hash, fsimg_hash, fsimg_size);

    let key_pair = read_keypair(key)?;
    let signature = key_pair.sign(hashes_yaml.as_bytes());
    let signature_base64 = base64::encode(signature);
    let signature_yaml = { format!("{}---\nsignature: {}", &hashes_yaml, &signature_base64) };

    Ok(signature_yaml)
}

/// Returns a temporary file with all the pseudo file definitions
fn pseudo_files(manifest: &Manifest) -> Result<NamedTempFile, Error> {
    let uid = manifest.uid;
    let gid = manifest.gid;

    let pseudo_directory = |dir: &Path, mode: u16| -> Vec<String> {
        let mut pseudos = Vec::new();
        // Each directory level needs to be passed to mksquashfs e.g:
        // /dev d 755 x x x
        // /dev/block d 755 x x x
        let mut p = PathBuf::from("/");
        for d in dir.iter().skip(1) {
            p.push(d);
            pseudos.push(format!("{} d {} {} {}", p.display(), mode, uid, gid));
        }
        pseudos
    };

    // Create mountpoints as pseudofiles/dirs
    let pseudos = manifest
        .mounts
        .iter()
        .flat_map(|(target, mount)| {
            match mount {
                Mount::Bind(Bind { options: flags, .. }) => {
                    let mode = if flags.contains(&MountOption::Rw) {
                        755
                    } else {
                        555
                    };
                    pseudo_directory(target.as_ref(), mode)
                }
                Mount::Persist => pseudo_directory(target.as_ref(), 755),
                Mount::Proc | Mount::Sysfs => pseudo_directory(target.as_ref(), 444),
                Mount::Resource { .. } => pseudo_directory(target.as_ref(), 555),
                Mount::Tmpfs { .. } => pseudo_directory(target.as_ref(), 755),
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
                    let mut pseudos = pseudo_directory(target.as_ref(), 755);

                    // Create chardevs
                    for (dev, major, minor) in &[
                        ("full", 1, 7),
                        ("null", 1, 3),
                        ("random", 1, 8),
                        ("tty", 5, 0),
                        ("urandom", 1, 9),
                        ("zero", 1, 5),
                    ] {
                        let target: &Path = target.as_ref();
                        let target = target.join(dev).display().to_string();
                        pseudos.push(format!(
                            "{} c {} {} {} {} {}",
                            target, 666, uid, gid, major, minor
                        ));
                    }

                    // Link fds
                    pseudos.push(format!("/proc/self/fd d 777 {} {}", uid, gid));
                    for (link, name) in &[
                        ("/proc/self/fd", "fd"),
                        ("/proc/self/fd/0", "stdin"),
                        ("/proc/self/fd/1", "stdout"),
                        ("/proc/self/fd/2", "stderr"),
                    ] {
                        let target: &Path = target.as_ref();
                        let target = target.join(name).display().to_string();
                        pseudos.push(format!("{} s {} {} {} {}", target, 777, uid, gid, link,));
                    }
                    pseudos
                }
            }
        })
        .collect::<Vec<String>>();

    let mut pseudo_file_entries =
        NamedTempFile::new().context("failed to create temporary file")?;

    pseudos.iter().try_for_each(|l| {
        writeln!(pseudo_file_entries, "{}", l).context("failed to create pseudo files")
    })?;

    Ok(pseudo_file_entries)
}

fn create_squashfs_img(
    manifest: &Manifest,
    root: &Path,
    image: &Path,
    squashfs_opts: &SquashfsOptions,
) -> Result<()> {
    let pseudo_files = pseudo_files(manifest)?;
    let mksquashfs = &squashfs_opts.mksquashfs;

    // Check root
    if !root.exists() {
        bail!("Root directory '{}' does not exist", &root.display());
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
        // remove trailing subversion if present (e.g. 4.4-e0485802)
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

    // Run mksquashfs to create image
    let mut cmd = Command::new(mksquashfs);
    cmd.arg(&root.display().to_string())
        .arg(&image.display().to_string())
        .arg("-no-progress")
        .arg("-comp")
        .arg(squashfs_opts.compression_algorithm.to_string())
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
    cmd.output()
        .with_context(|| format!("failed to execute '{}'", mksquashfs.display()))?;
    if !image.exists() {
        bail!(
            "'{}' failed to create '{}'",
            mksquashfs.display(),
            &image.display()
        );
    }

    Ok(())
}

fn unpack_squashfs(image: &Path, out: &Path, unsquashfs: &Path) -> Result<()> {
    let squashfs_root = out.join("squashfs-root");

    if !image.exists() {
        bail!("Squashfs image '{}' does not exist", &image.display());
    }
    let mut cmd = Command::new(unsquashfs);
    cmd.arg("-dest")
        .arg(&squashfs_root.display().to_string())
        .arg(&image.display().to_string());

    cmd.output()
        .with_context(|| format!("Error while executing '{}'", unsquashfs.display(),))?;

    Ok(())
}

fn write_npk<W: Write + Seek>(
    npk: W,
    manifest: &Manifest,
    fsimg: &Path,
    signature: Option<&str>,
) -> Result<()> {
    let mut fsimg =
        fs::File::open(&fsimg).with_context(|| format!("failed to open '{}'", &fsimg.display()))?;
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let manifest_string =
        serde_yaml::to_string(&manifest).context("failed to serialize manifest")?;

    let mut zip = zip::ZipWriter::new(npk);
    zip.set_comment(
        serde_yaml::to_string(&Meta { version: VERSION }).context("failed to serialize meta")?,
    );

    if let Some(signature) = signature {
        zip.start_file(SIGNATURE_NAME, options)?;
        zip.write_all(signature.as_bytes())
            .context("failed to write signature to NPK")?;
    }

    zip.start_file(MANIFEST_NAME, options)
        .context("failed to write manifest to NPK")?;
    zip.write_all(manifest_string.as_bytes())
        .context("failed to convert manifest to NPK")?;

    // We need to ensure that the fs.img start at an offset of 4096 so we add empty (zeros) ZIP
    // 'extra data' to inflate the header of the ZIP file.
    // See chapter 4.3.6 of APPNOTE.TXT
    // (https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
    zip.start_file_aligned(FS_IMG_NAME, options, BLOCK_SIZE as u16)
        .context("Could create aligned zip-file")?;
    io::copy(&mut fsimg, &mut zip)
        .context("failed to write the filesystem image to the archive")?;
    Ok(())
}

/// Open a Zip file
fn open(path: &Path) -> Result<Zip<BufReader<fs::File>>> {
    let file =
        fs::File::open(&path).with_context(|| format!("failed to open '{}'", &path.display()))?;
    ZipArchive::new(BufReader::new(file))
        .with_context(|| format!("failed to parse ZIP format: '{}'", &path.display()))
}
