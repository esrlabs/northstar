use crate::npk::{
    dm_verity::{append_dm_verity_block, Error as VerityError, VerityHeader, BLOCK_SIZE},
    manifest::{Bind, Manifest, Mount, MountOption},
};
use ed25519_dalek::{
    ed25519::signature::Signature, Keypair, PublicKey, SecretKey, SignatureError, Signer,
    SECRET_KEY_LENGTH,
};
use itertools::Itertools;
use rand::rngs::OsRng;
use regex::Regex;
use semver::Version;
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
use zip::{result::ZipError, ZipArchive};

/// Manifest version supported by the runtime
pub const VERSION: Version = semver::Version {
    major: 0,
    minor: 0,
    patch: 1,
    pre: vec![],
    build: vec![],
};

// Binaries
const MKSQUASHFS: &str = "mksquashfs";
const MKSQUASHFS_MAJOR_VERSION_MINIMUM: u32 = 4;
const MKSQUASHFS_MINOR_VERSION_MINIMUM: u32 = 1;
const UNSQUASHFS: &str = "unsquashfs";

// File name and directory components
const FS_IMG_NAME: &str = "fs.img";
const MANIFEST_NAME: &str = "manifest.yaml";
const SIGNATURE_NAME: &str = "signature.yaml";
const FS_IMG_BASE: &str = "fs";
const FS_IMG_EXT: &str = "img";
const NPK_EXT: &str = "npk";

type Zip<R> = ZipArchive<R>;

/// NPK loading error
#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Manifest error: {0}")]
    Manifest(String),
    #[error("IO: {context}")]
    Io {
        context: String,
        #[source]
        error: io::Error,
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
    #[error("Comment malformed: {0}")]
    MalformedComment(String),
    #[error("Hashes malformed: {0}")]
    MalformedHashes(String),
    #[error("Signature malformed: {0}")]
    MalformedSignature(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Invalid compression algorithm")]
    InvalidCompressionAlgorithm,
    #[error("Version mismatch {0} vs {1}")]
    Version(Version, Version),
}

impl Error {
    fn io<T: ToString>(context: T, error: io::Error) -> Error {
        Error::Io {
            context: context.to_string(),
            error,
        }
    }
}

/// NPK archive comment
#[derive(Debug, Serialize, Deserialize)]
pub struct Meta {
    /// Version
    pub version: Version,
}

/// NPK Hashes
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Hashes {
    /// Hash of the manifest yaml
    pub manifest_hash: String,
    /// Fs hash
    pub fs_hash: String,
    /// Verity hash
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
        let mut zip = Zip::new(reader).map_err(|error| Error::Zip {
            context: "Failed to open NPK".to_string(),
            error,
        })?;

        let meta = meta(&zip)?;
        // TODO: Should we do semver comparison here?
        if meta.version != VERSION {
            return Err(Error::Version(meta.version, VERSION));
        }

        let hashes = hashes(&mut zip, key)?;
        let manifest = manifest(&mut zip, hashes.as_ref())?;
        let (fs_img_offset, fs_img_size) = {
            let fs_img = &zip.by_name(FS_IMG_NAME).map_err(|e| Error::Zip {
                context: format!("Failed to locate {} in ZIP file", &FS_IMG_NAME),
                error: e,
            })?;
            (fs_img.data_start(), fs_img.size())
        };

        let mut file = zip.into_inner();
        let verity_header = match &hashes {
            Some(hs) => {
                file.seek(SeekFrom::Start(fs_img_offset + hs.fs_verity_offset))
                    .map_err(|e| Error::Io {
                        context: format!("{} too small to extract verity header", &FS_IMG_NAME),
                        error: e,
                    })?;
                Some(VerityHeader::from_bytes(&mut file).map_err(Error::Verity)?)
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
        fs::File::open(npk)
            .map_err(|error| Error::Io {
                context: format!("Open file {}", npk.display()),
                error,
            })
            .map(BufReader::new)
            .and_then(|r| Npk::from_reader(r, key))
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

fn meta<R: Read + Seek>(zip: &Zip<R>) -> Result<Meta, Error> {
    serde_yaml::from_slice(zip.comment()).map_err(|e| Error::MalformedComment(e.to_string()))
}

fn hashes<R: Read + Seek>(
    mut zip: &mut Zip<R>,
    key: Option<&PublicKey>,
) -> Result<Option<Hashes>, Error> {
    match key {
        Some(k) => {
            let signature_content = read_to_string(&mut zip, SIGNATURE_NAME)?;
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

fn manifest<R: Read + Seek>(
    mut zip: &mut Zip<R>,
    hashes: Option<&Hashes>,
) -> Result<Manifest, Error> {
    let content = read_to_string(&mut zip, MANIFEST_NAME)?;
    if let Some(Hashes { manifest_hash, .. }) = &hashes {
        let expected_hash = hex::decode(manifest_hash)
            .map_err(|e| Error::Manifest(format!("Failed to parse manifest hash {}", e)))?;
        let actual_hash = Sha256::digest(content.as_bytes());
        if expected_hash != actual_hash.as_slice() {
            return Err(Error::Manifest(format!(
                "Invalid manifest hash (expected={} actual={})",
                manifest_hash,
                hex::encode(actual_hash)
            )));
        }
    }
    Manifest::from_str(&content)
        .map_err(|e| Error::Manifest(format!("Failed to parse manifest: {}", e)))
}

fn read_to_string<R: Read + Seek>(zip: &mut Zip<R>, name: &str) -> Result<String, Error> {
    let mut file = zip.by_name(name).map_err(|error| Error::Zip {
        context: format!("Failed to locate {} in ZIP file", name),
        error,
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

    fn squashfs_opts(mut self, opts: &SquashfsOpts) -> Builder {
        self.squashfs_opts = opts.clone();
        self
    }

    fn build<W: Write + Seek>(&self, writer: W) -> Result<(), Error> {
        // Create squashfs image
        let tmp = tempfile::TempDir::new().map_err(|e| Error::Io {
            context: "Failed to create temporary directory".to_string(),
            error: e,
        })?;
        let fsimg = tmp.path().join(&FS_IMG_BASE).with_extension(&FS_IMG_EXT);
        create_squashfs_img(&self.manifest, &self.root, &fsimg, &self.squashfs_opts)?;

        // Sign and write NPK
        if let Some(key) = &self.key {
            let signature = sign_npk(key, &fsimg, &self.manifest)?;
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
            _ => Err(Error::InvalidCompressionAlgorithm),
        }
    }
}

/// Squashfs Options
#[derive(Clone, Debug)]
pub struct SquashfsOpts {
    /// The compression algorithm used (default gzip)
    pub comp: CompressionAlgorithm,
    /// Size of the blocks of data compressed separately
    pub block_size: Option<u32>,
}

impl Default for SquashfsOpts {
    fn default() -> Self {
        SquashfsOpts {
            comp: CompressionAlgorithm::Gzip,
            block_size: None,
        }
    }
}

/// Create an NPK for the northstar runtime.
/// sextant collects the artifacts in a given container directory, creates and signs the necessary metadata
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
/// sextant pack \
/// --manifest examples/hello/manifest.yaml \
/// --root examples/hello/root \
/// --out target/northstar/repository \
/// --key examples/keys/northstar.key \
pub fn pack(manifest: &Path, root: &Path, out: &Path, key: Option<&Path>) -> Result<(), Error> {
    pack_with(manifest, root, out, key, &SquashfsOpts::default())
}

/// Create an NPK with special `squashfs` options
/// sextant collects the artifacts in a given container directory, creates and signs the necessary metadata
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
/// sextant pack \
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
    squashfs_opts: &SquashfsOpts,
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
    let npk = fs::File::create(&dest).map_err(|e| Error::Io {
        context: format!("Failed to create NPK: '{}'", &dest.display()),
        error: e,
    })?;
    builder.build(npk)
}

/// Extract the npk content to `out`
pub fn unpack(npk: &Path, out: &Path) -> Result<(), Error> {
    let mut zip = open(npk)?;
    zip.extract(&out).map_err(|e| Error::Zip {
        context: format!("Failed to extract NPK to '{}'", &out.display()),
        error: e,
    })?;
    let fsimg = out.join(&FS_IMG_NAME);
    unpack_squashfs(&fsimg, out)
}

/// Generate a keypair suitable for signing and verifying NPKs
pub fn generate_key(name: &str, out: &Path) -> Result<(), Error> {
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

    fn write(data: &[u8], path: &Path) -> Result<(), Error> {
        let mut file = fs::File::create(&path).map_err(|e| Error::Io {
            context: format!("Failed to create '{}'", &path.display()),
            error: e,
        })?;
        file.write_all(data).map_err(|e| Error::Io {
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
    write(&key_pair.public.to_bytes(), &pub_key)?;
    write(&key_pair.secret.to_bytes(), &prv_key)?;

    Ok(())
}

fn read_manifest(path: &Path) -> Result<Manifest, Error> {
    let file = fs::File::open(&path)
        .map_err(|e| Error::io(format!("Failed to open '{}'", &path.display()), e))?;
    Manifest::from_reader(&file)
        .map_err(|e| Error::Manifest(format!("Failed to parse '{}': {}", &path.display(), e)))
}

fn read_keypair(key_file: &Path) -> Result<Keypair, Error> {
    let mut secret_key_bytes = [0u8; SECRET_KEY_LENGTH];
    fs::File::open(&key_file)
        .map_err(|e| Error::io(format!("Failed to open '{}'", &key_file.display()), e))?
        .read_exact(&mut secret_key_bytes)
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

fn gen_hashes_yaml(
    manifest: &Manifest,
    fsimg: &Path,
    fsimg_size: u64,
    hash: &[u8],
) -> Result<String, Error> {
    // Create hashes YAML
    let mut sha256 = Sha256::new();
    sha2::digest::Update::update(&mut sha256, manifest.to_string().as_bytes());
    let manifest_hash = sha256.finalize();
    let mut sha256 = Sha256::new();
    let mut fsimg = fs::File::open(&fsimg)
        .map_err(|e| Error::io(format!("Failed to open '{}'", &fsimg.display()), e))?;
    io::copy(&mut fsimg, &mut sha256).map_err(|e| Error::Io {
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
        hash.iter().format(""),
        fsimg_size
    );

    Ok(hashes)
}

fn sign_npk(key: &Path, fsimg: &Path, manifest: &Manifest) -> Result<String, Error> {
    let fsimg_size = fs::metadata(&fsimg)
        .map_err(|e| Error::Io {
            context: format!("Failed to read file size: '{}'", &fsimg.display()),
            error: e,
        })?
        .len();
    let root_hash: &[u8] = &append_dm_verity_block(fsimg, fsimg_size).map_err(Error::Verity)?;
    let key_pair = read_keypair(key)?;
    let hashes_yaml = gen_hashes_yaml(manifest, fsimg, fsimg_size, root_hash)?;
    let signature_yaml = sign_hashes(&key_pair, &hashes_yaml);

    Ok(signature_yaml)
}

/// Returns a temporary file with all the pseudo file definitions
fn gen_pseudo_files(manifest: &Manifest) -> Result<NamedTempFile, Error> {
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
        .map(|(target, mount)| {
            match mount {
                Mount::Bind(Bind { options: flags, .. }) => {
                    let mode = if flags.contains(&MountOption::Rw) {
                        755
                    } else {
                        555
                    };
                    pseudo_directory(target, mode)
                }
                Mount::Persist => pseudo_directory(target, 755),
                Mount::Proc => pseudo_directory(target, 444),
                Mount::Resource { .. } => pseudo_directory(target, 555),
                Mount::Tmpfs { .. } => pseudo_directory(target, 755),
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
                    let mut pseudos = pseudo_directory(target, 755);

                    // Create chardevs
                    for (dev, major, minor) in &[
                        ("full", 1, 7),
                        ("null", 1, 3),
                        ("random", 1, 8),
                        ("tty", 5, 0),
                        ("urandom", 1, 9),
                        ("zero", 1, 5),
                    ] {
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
                        let target = target.join(name).display().to_string();
                        pseudos.push(format!("{} s {} {} {} {}", target, 777, uid, gid, link,));
                    }
                    pseudos
                }
            }
        })
        .flatten()
        .collect::<Vec<String>>();

    let mut pseudo_file_entries = NamedTempFile::new()
        .map_err(|error| Error::io("Failed to create temporary file", error))?;

    pseudos.iter().try_for_each(|l| {
        writeln!(pseudo_file_entries, "{}", l)
            .map_err(|e| Error::io("Failed to create pseudo files", e))
    })?;

    Ok(pseudo_file_entries)
}

fn sign_hashes(key_pair: &Keypair, hashes_yaml: &str) -> String {
    let signature = key_pair.sign(hashes_yaml.as_bytes());
    let signature_base64 = base64::encode(signature);
    let key_id = "northstar";
    format!(
        "{}---\nkey: {}\nsignature: {}",
        &hashes_yaml, &key_id, &signature_base64
    )
}

fn create_squashfs_img(
    manifest: &Manifest,
    root: &Path,
    image: &Path,
    squashfs_opts: &SquashfsOpts,
) -> Result<(), Error> {
    let pseudo_files = gen_pseudo_files(manifest)?;

    which::which(&MKSQUASHFS)
        .map_err(|_| Error::Squashfs(format!("Failed to locate '{}'", &MKSQUASHFS)))?;
    if !root.exists() {
        return Err(Error::Squashfs(format!(
            "Root directory '{}' does not exist",
            &root.display()
        )));
    }

    // Check mksquashfs version
    let regex = Regex::new(r"([0-9]*\.[0-9]*)").unwrap(); // unwrap(): Creating regex from constant expression will never fail
    let first_line = String::from_utf8(
        Command::new(&MKSQUASHFS)
            .arg("-version")
            .output()
            .map_err(|e| Error::Squashfs(format!("Failed to execute '{}': {}", &MKSQUASHFS, e)))?
            .stdout,
    )
    .map_err(|e| Error::Squashfs(format!("Failed to parse mksquashfs output: {}", e)))?
    .lines()
    .next()
    .unwrap_or_default()
    .to_string();
    if let Some(captures) = regex.captures(&first_line) {
        if let Some(m) = captures.get(0) {
            let mut split = m.as_str().split('.');
            let major = split
                .next()
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or_default();
            let minor = split
                .next()
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or_default();
            if (major < MKSQUASHFS_MAJOR_VERSION_MINIMUM)
                || (major == MKSQUASHFS_MAJOR_VERSION_MINIMUM
                    && minor < MKSQUASHFS_MINOR_VERSION_MINIMUM)
            {
                return Err(Error::Squashfs(format!(
                    "Detected mksquashfs version {}.{} is too old. The required minimum version is {}.{}.",
                    major, minor, MKSQUASHFS_MAJOR_VERSION_MINIMUM, MKSQUASHFS_MINOR_VERSION_MINIMUM
                )));
            }
        }
    } else {
        return Err(Error::Squashfs(
            "Failed to determine mksquashfs version".to_string(),
        ));
    }

    let mut cmd = Command::new(&MKSQUASHFS);
    cmd.arg(&root.display().to_string())
        .arg(&image.display().to_string())
        .arg("-no-progress")
        .arg("-comp")
        .arg(squashfs_opts.comp.to_string())
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
        .map_err(|e| Error::Squashfs(format!("Failed to execute '{}': {}", &MKSQUASHFS, e)))?;
    if !image.exists() {
        return Err(Error::Squashfs(format!(
            "'{}' failed to create '{}'",
            &MKSQUASHFS,
            &image.display()
        )));
    }

    Ok(())
}

fn unpack_squashfs(image: &Path, out: &Path) -> Result<(), Error> {
    let squashfs_root = out.join("squashfs-root");

    which::which(&UNSQUASHFS)
        .map_err(|_| Error::Squashfs(format!("Failed to locate '{}'", &UNSQUASHFS)))?;
    if !image.exists() {
        return Err(Error::Squashfs(format!(
            "Squashfs image '{}' does not exist",
            &image.display()
        )));
    }
    let mut cmd = Command::new(&UNSQUASHFS);
    cmd.arg("-dest")
        .arg(&squashfs_root.display().to_string())
        .arg(&image.display().to_string());

    cmd.output()
        .map_err(|e| Error::Squashfs(format!("Error while executing '{}': {}", &UNSQUASHFS, e)))
        .map(drop)
}

fn write_npk<W: Write + Seek>(
    npk: W,
    manifest: &Manifest,
    fsimg: &Path,
    signature: Option<&str>,
) -> Result<(), Error> {
    let mut fsimg = fs::File::open(&fsimg)
        .map_err(|e| Error::io(format!("Failed to open '{}'", &fsimg.display()), e))?;
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let manifest_string = serde_yaml::to_string(&manifest)
        .map_err(|e| Error::Manifest(format!("Failed to serialize manifest: {}", e)))?;

    let mut zip = zip::ZipWriter::new(npk);
    zip.set_comment(serde_yaml::to_string(&Meta { version: VERSION }).unwrap());

    if let Some(signature) = signature {
        || -> Result<(), io::Error> {
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

    // We need to ensure that the fs.img start at an offset of 4096 so we add empty (zeros) ZIP
    // 'extra data' to inflate the header of the ZIP file.
    // See chapter 4.3.6 of APPNOTE.TXT
    // (https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
    zip.start_file_aligned(FS_IMG_NAME, options, BLOCK_SIZE as u16)
        .map_err(|e| Error::Zip {
            context: "Could create aligned zip-file".to_string(),
            error: e,
        })?;
    io::copy(&mut fsimg, &mut zip)
        .map_err(|e| Error::Io {
            context: "Failed to write the filesystem image to the archive".to_string(),
            error: e,
        })
        .map(drop)
}

/// Open a Zip file
pub fn open(path: &Path) -> Result<Zip<BufReader<fs::File>>, Error> {
    let file = fs::File::open(&path)
        .map_err(|e| Error::io(format!("Failed to open '{}'", &path.display()), e))?;
    zip::ZipArchive::new(BufReader::new(file)).map_err(|error| Error::Zip {
        context: format!("Failed to parse ZIP format: '{}'", &path.display()),
        error,
    })
}
