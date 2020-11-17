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

use crate::dm_verity::{append_dm_verity_block, BLOCK_SIZE};
use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer, SECRET_KEY_LENGTH};
use itertools::Itertools;
use north::manifest::{Manifest, Mount, MountFlag};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::{
    fs,
    fs::File,
    io,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;
use zip::ZipArchive;

const MKSQUASHFS_BIN: &str = "mksquashfs";
const UNSQUASHFS_BIN: &str = "unsquashfs";

// user and group id for squashfs pseudo directories ('/dev', '/proc', '/tmp' etc.)
const PSEUDO_DIR_UID: u32 = 1000;
const PSEUDO_DIR_GID: u32 = 1000;

// file name and directory components
const NPK_EXT: &str = "npk";
const FS_IMG_BASE: &str = "fs";
const FS_IMG_EXT: &str = "img";
const FS_IMG_NAME: &str = "fs.img";
const MANIFEST_BASE: &str = "manifest";
const MANIFEST_EXT: &str = "yaml";
const MANIFEST_NAME: &str = "manifest.yaml";
const SIGNATURE_NAME: &str = "signature.yaml";
const ROOT_DIR_NAME: &str = "root";

/// Create an NPK for the north runtime.
/// sextant collects the artifacts in a given container directory, creates and signs the necessary metadata
/// and packs the results into a zipped NPK file.
///
/// # Example
///
/// To build the 'hello' example container:
///
/// sextant pack \
/// --dir examples/container/hello \
/// --out target/north/registry \
/// --key examples/keys/north.key \
pub fn pack(dir: &Path, out: &Path, key: &Path) -> Result<()> {
    let manifest = read_manifest(dir)?;

    // add manifest and root dir to tmp dir
    let tmp = tempfile::TempDir::new().with_context(|| "Failed to create temporary directory")?;
    let tmp_root = copy_src_root_to_tmp(&dir, &tmp)?;
    let tmp_manifest = write_manifest(&manifest, &tmp)?;

    // create filesystem image
    let fsimg = tmp.path().join(&FS_IMG_BASE).with_extension(&FS_IMG_EXT);
    create_fs_img(&tmp_root, &manifest, &fsimg)?;

    // create NPK
    let signature = sign_npk(&key, &fsimg, &tmp_manifest)?;
    write_npk(&out, &manifest, &fsimg, &signature)
        .with_context(|| format!("Failed to create NPK at {}", &out.display()))?;
    Ok(())
}

pub fn unpack(npk: &Path, out: &Path) -> Result<()> {
    let mut zip = open_zipped_npk(&npk)?;
    zip.extract(&out)
        .with_context(|| format!("Failed to extract NPK to '{}'", &out.display()))?;
    let fsimg = out.join(&FS_IMG_NAME);
    unpack_squashfs(&fsimg, &out)
        .with_context(|| format!("Failed to unsquash image at '{}'", &fsimg.display()))?;
    Ok(())
}

pub fn inspect(npk: &Path) -> Result<()> {
    let mut zip = open_zipped_npk(&npk)?;
    let mut print_buf: String = String::new();
    println!(
        "{}",
        format!("# inspection of '{}'", &npk.display()).green()
    );
    println!("{}", "## NPK Content".to_string().green());
    zip.file_names().for_each(|f| println!("{}", f));
    println!();

    // print manifest
    let mut man = zip
        .by_name(MANIFEST_NAME)
        .context("Failed to find manifest in NPK")?;
    println!("{}", format!("## {}", MANIFEST_NAME).green());
    man.read_to_string(&mut print_buf)
        .with_context(|| "Failed to read manifest")?;
    println!("{}", &print_buf);
    print!("\n\n");
    print_buf.clear();
    drop(man);

    // print signature
    let mut sig = zip
        .by_name(SIGNATURE_NAME)
        .context("Failed to find signature in NPK")?;
    println!("{}", format!("## {}", SIGNATURE_NAME).green());
    sig.read_to_string(&mut print_buf)
        .with_context(|| "Failed to read signature")?;
    println!("{}", &print_buf);
    print!("\n\n");
    print_buf.clear();
    drop(sig);

    // print squashfs listing
    let mut dest_fsimage = tempfile::NamedTempFile::new().context("Failed to create tmp file")?;
    let mut src_fsimage = zip
        .by_name(FS_IMG_NAME)
        .context("Failed to find filesystem image in NPK")?;
    io::copy(&mut src_fsimage, &mut dest_fsimage)?;
    let path = dest_fsimage.path();
    print_squashfs(&path)?;

    Ok(())
}

/// Generate a keypair suitable for signing and verifying NPKs
pub fn gen_key(name: &str, out: &Path) -> Result<()> {
    let mut csprng = OsRng {};
    let key_pair = Keypair::generate(&mut csprng);
    let pub_key = out.join(name).with_extension("pub");
    let prv_key = out.join(name).with_extension("key");
    assume_non_existing(&pub_key)?;
    assume_non_existing(&prv_key)?;

    fn write(data: &[u8], path: &Path) -> Result<()> {
        let mut file = File::create(&path)
            .with_context(|| format!("Failed to create '{}'", &path.display()))?;
        file.write_all(&data)
            .with_context(|| format!("Failed to write to '{}'", &path.display()))?;
        Ok(())
    }
    write(&key_pair.public.to_bytes(), &pub_key)?;
    write(&key_pair.secret.to_bytes(), &prv_key)?;
    Ok(())
}

fn open_zipped_npk(npk: &&Path) -> Result<ZipArchive<File>> {
    let zip = zip::ZipArchive::new(
        File::open(&npk).with_context(|| format!("Failed to open NPK at '{}'", &npk.display()))?,
    )
    .with_context(|| format!("Failed to parse ZIP format of NPK at '{}'", &npk.display()))?;
    Ok(zip)
}

fn read_manifest(src: &Path) -> Result<Manifest> {
    let manifest_path = src.join(MANIFEST_BASE).with_extension(&MANIFEST_EXT);
    let manifest = std::fs::File::open(&manifest_path)
        .with_context(|| format!("Failed to open manifest at '{}'", &manifest_path.display()))?;
    serde_yaml::from_reader(manifest)
        .with_context(|| format!("Failed to parse manifest '{}'", &manifest_path.display()))
}

fn write_manifest(manifest: &Manifest, tmp: &TempDir) -> Result<PathBuf> {
    let tmp_manifest_path = tmp
        .path()
        .join(&MANIFEST_BASE)
        .with_extension(&MANIFEST_EXT);
    let tmp_manifest = File::create(&tmp_manifest_path)
        .with_context(|| format!("Failed to create '{}'", &tmp_manifest_path.display()))?;
    serde_yaml::to_writer(&tmp_manifest, &manifest)
        .with_context(|| "Failed to serialize manifest")?;
    Ok(tmp_manifest_path)
}

fn read_keypair(key_file: &Path) -> Result<Keypair> {
    let mut secret_key_bytes = [0u8; SECRET_KEY_LENGTH];
    File::open(&key_file)
        .with_context(|| format!("Failed to open '{}'", &key_file.display()))?
        .read_exact(&mut secret_key_bytes)
        .with_context(|| format!("Failed to read key data from '{}'", &key_file.display()))?;
    let secret_key = SecretKey::from_bytes(&secret_key_bytes)
        .with_context(|| format!("Failed to derive secret key from '{}'", &key_file.display()))?;
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
) -> Result<String> {
    // Create hashes YAML
    let mut sha256 = Sha256::new();
    let mut tmp_manifest = File::open(&tmp_manifest_path)
        .with_context(|| format!("Failed to open '{}'", &tmp_manifest_path.display()))?;
    io::copy(&mut tmp_manifest, &mut sha256)?;
    let manifest_hash = sha256.finalize();
    let mut sha256 = Sha256::new();
    let mut fsimg = File::open(&fsimg_path)
        .with_context(|| format!("Failed to open '{}'", &fsimg_path.display()))?;
    io::copy(&mut fsimg, &mut sha256).context("Failed to read fs image")?;

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

fn sign_npk(key_file: &Path, fsimg: &Path, tmp_manifest: &Path) -> Result<String> {
    let fsimg_size = fs::metadata(&fsimg)
        .with_context(|| format!("Fail to read read size of '{}'", &fsimg.display()))?
        .len();
    let root_hash = append_dm_verity_block(&fsimg, fsimg_size)?;
    let key_pair = read_keypair(&key_file)?;
    let hashes_yaml = gen_hashes_yaml(&tmp_manifest, &fsimg, fsimg_size, &root_hash)?;
    let signature_yaml = sign_hashes(&key_pair, &hashes_yaml);
    Ok(signature_yaml)
}

fn gen_pseudo_files(manifest: &Manifest) -> Result<Vec<(String, u32)>> {
    let mut pseudo_files: Vec<(String, u32)> = vec![];
    if manifest.init.is_some() {
        pseudo_files = vec![
            ("/dev".to_string(), 444),
            ("/proc".to_string(), 444),
            ("/tmp".to_string(), 444),
        ];
    }
    for mount in manifest.mounts.iter() {
        match mount {
            Mount::Resource { target, .. } => {
                // In order to support mount points with multiple path segments, we need to call mksquashfs multiple times:
                // e.g. to support res/foo in our image, we need to add /res/foo AND /res
                // ==> mksquashfs ... -p "/res/foo d 444 1000 1000"  -p "/res d 444 1000 1000" */
                let trail = path_trail(&target);
                for path in trail {
                    pseudo_files.push((path.display().to_string(), 555));
                }
            }
            Mount::Bind { target, flags, .. } | Mount::Persist { target, flags, .. } => {
                let mode = if flags.contains(&MountFlag::Rw) {
                    777
                } else {
                    444
                };
                pseudo_files.push((target.display().to_string(), mode));
            }
            Mount::Tmpfs { target, .. } => {
                let mode = 777;
                pseudo_files.push((target.display().to_string(), mode));
            }
        }
    }
    Ok(pseudo_files)
}

fn sign_hashes(key_pair: &Keypair, hashes_yaml: &str) -> String {
    let signature = key_pair.sign(hashes_yaml.as_bytes());
    let signature_base64 = base64::encode(signature);
    let key_id = "north";
    let signature_yaml = format!(
        "{}---\nkey: {}\nsignature: {}",
        &hashes_yaml, &key_id, &signature_base64
    );
    signature_yaml
}

fn copy_src_root_to_tmp(src: &Path, tmp: &TempDir) -> Result<PathBuf> {
    let src_root = src.join(&ROOT_DIR_NAME);
    let tmp_root = tmp.path().join(&ROOT_DIR_NAME);
    let options = fs_extra::dir::CopyOptions::new();
    if src_root.exists() {
        fs_extra::dir::copy(&src_root, &tmp, &options).with_context(|| {
            format!(
                "Failed to copy from '{}' to '{}'",
                &src_root.display(),
                &tmp.path().display()
            )
        })?;
    } else {
        // create empty root dir at destination if we have nothing to copy
        fs_extra::dir::create(&tmp_root, false)
            .with_context(|| format!("Failed to create directory '{}'", &tmp_root.display()))?;
    }
    Ok(tmp_root)
}

fn create_fs_img(tmp_root: &Path, manifest: &Manifest, fsimg: &Path) -> Result<()> {
    let pseudo_files =
        gen_pseudo_files(&manifest).with_context(|| "Failed to generate list of pseudo files")?;
    create_squashfs(&tmp_root, &fsimg, &pseudo_files)
        .with_context(|| format!("Failed to create squashfs in '{}'", &fsimg.display()))?;
    Ok(())
}

fn create_squashfs(out: &Path, src: &Path, pseudo_dirs: &[(String, u32)]) -> Result<()> {
    #[cfg(target_os = "linux")]
    let compression_alg = "gzip";
    #[cfg(not(target_os = "linux"))]
    let compression_alg = "zstd";

    if which::which(&MKSQUASHFS_BIN).is_err() {
        return Err(anyhow!("Failed to locate '{}'", &MKSQUASHFS_BIN));
    }
    if !out.exists() {
        return Err(anyhow!(
            "Output directory '{}' does not exist",
            &out.display()
        ));
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
        .with_context(|| format!("Failed to execute '{}'", &MKSQUASHFS_BIN))?;

    if !src.exists() {
        Err(anyhow!(
            "'{}' did not create '{}'",
            &MKSQUASHFS_BIN,
            &FS_IMG_NAME
        ))
    } else {
        Ok(())
    }
}

fn unpack_squashfs(image: &Path, out: &Path) -> Result<()> {
    if which::which(&UNSQUASHFS_BIN).is_err() {
        return Err(anyhow!("Failed to locate '{}'", &UNSQUASHFS_BIN));
    }
    if !image.exists() {
        return Err(anyhow!(
            "Squashfs image at '{}' does not exist",
            &image.display()
        ));
    }
    let squashfs_root = out.join("squashfs-root");
    let mut cmd = Command::new(&UNSQUASHFS_BIN);
    cmd.arg("-dest")
        .arg(&squashfs_root.display().to_string())
        .arg(&image.display().to_string())
        .output()
        .with_context(|| format!("Error while executing '{}'", &UNSQUASHFS_BIN))?;
    Ok(())
}

fn write_npk(npk: &Path, manifest: &Manifest, fsimg: &Path, signature: &str) -> Result<()> {
    let npk = npk
        .join(format!(
            "{}-{}.",
            &manifest.name,
            &manifest.version.to_string()
        ))
        .with_extension(&NPK_EXT);
    let npk = File::create(&npk)
        .with_context(|| format!("Failed to create NPK at '{}'", &npk.display()))?;
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut zip = zip::ZipWriter::new(&npk);
    zip.start_file(SIGNATURE_NAME, options)?;
    zip.write_all(signature.as_bytes())?;
    zip.start_file(MANIFEST_NAME, options)?;
    let manifest_string = serde_yaml::to_string(&manifest)?;
    zip.write_all(manifest_string.as_bytes())?;

    /* We need to ensure that the fs.img start at an offset of 4096 so we add empty (zeros) ZIP
     * 'extra data' to inflate the header of the ZIP file.
     * See chapter 4.3.6 of APPNOTE.TXT
     * (https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) */
    zip.start_file_aligned(FS_IMG_NAME, options, BLOCK_SIZE as u16)?;
    let mut fsimg =
        File::open(&fsimg).with_context(|| format!("Failed to open '{}'", &fsimg.display()))?;
    io::copy(&mut fsimg, &mut zip)?;

    Ok(())
}

fn print_squashfs(fsimg_path: &Path) -> Result<()> {
    which::which(&UNSQUASHFS_BIN)
        .with_context(|| anyhow!("Failed to find '{}'", &UNSQUASHFS_BIN))?;

    let mut cmd = Command::new(&UNSQUASHFS_BIN);
    cmd.arg("-ll").arg(fsimg_path.display().to_string());

    let output = cmd
        .output()
        .with_context(|| format!("Failed to execute '{}'", &UNSQUASHFS_BIN))?;

    println!("{}", String::from_utf8_lossy(&output.stdout));

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

fn assume_non_existing(path: &Path) -> Result<()> {
    if path.exists() {
        Err(anyhow!("File '{}' already exists", &path.display()))
    } else {
        Ok(())
    }
}
