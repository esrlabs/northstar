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

use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer, SECRET_KEY_LENGTH};
use itertools::Itertools;
use north::manifest::{Manifest, Mount, MountFlag};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    fs,
    fs::{File, OpenOptions},
    io,
    io::{BufReader, Read, Seek, SeekFrom::Start, Write},
    path::{Path, PathBuf},
    process::Command,
};
use tempdir::TempDir;
use uuid::Uuid;
use zip::ZipArchive;

const MKSQUASHFS_BIN: &str = "mksquashfs";
const UNSQUASHFS_BIN: &str = "unsquashfs";

// user and group id for squashfs pseudo directories ('/dev', '/proc', '/tmp' etc.)
const PSEUDO_DIR_UID: u32 = 1000;
const PSEUDO_DIR_GID: u32 = 1000;

// constants for verity header generation
const SHA256_SIZE: usize = 32;
const BLOCK_SIZE: usize = 4096;

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
/// --platform x86_64-unknown-linux-gnu
pub fn pack(src_path: &Path, out_path: &Path, key_file_path: &Path) -> Result<()> {
    let manifest = read_manifest(src_path)?;

    // add manifest and root dir to tmp dir
    let tmp = create_tmp_dir()?;
    let tmp_root_path = copy_src_root_to_tmp(&src_path, &tmp)?;
    let tmp_manifest_path = write_manifest(&manifest, &tmp)?;

    // create filesystem image
    let fsimg_path = tmp.path().join(&FS_IMG_BASE).with_extension(&FS_IMG_EXT);
    create_fs_img(&tmp_root_path, &manifest, &fsimg_path)?;

    // create NPK
    let signature = gen_signature_yaml(&key_file_path, &fsimg_path, &tmp_manifest_path)?;

    write_npk(&out_path, &manifest, &fsimg_path, &signature)
        .with_context(|| format!("Failed to create NPK in {}", &out_path.display()))?;
    Ok(())
}

pub fn inspect(npk: &Path) -> Result<()> {
    let tmp = create_tmp_dir()?;

    // Print NPK file list
    println!(
        "{}",
        format!("# inspection of '{}'", &npk.display()).green()
    );
    let npk = File::open(&npk).with_context(|| format!("Cannot open NPK '{}'", &npk.display()))?;
    let mut zip_writer = zip::ZipArchive::new(&npk)?;
    println!("{}", "## NPK Content".to_string().green());
    print_zip(&mut zip_writer)?;

    // Extract NPK and print contents
    zip_writer.extract(&tmp)?;
    let manifest_path = tmp.path().join(&MANIFEST_NAME);
    let signature_path = tmp.path().join(&SIGNATURE_NAME);
    let fsimg_path = tmp.path().join(&FS_IMG_NAME);
    if manifest_path.exists() {
        println!("{}", format!("## {}", &MANIFEST_NAME).green());
        print_file(&manifest_path)?;
    } else {
        return Err(anyhow!("Missing manifest"));
    }
    if signature_path.exists() {
        println!("{}", format!("## {}", &SIGNATURE_NAME).green());
        print_file(&signature_path)?;
    } else {
        return Err(anyhow!("Missing signature"));
    }
    if fsimg_path.exists() {
        println!("{}", format!("## {}", &FS_IMG_NAME).green());
        print_squashfs(&fsimg_path)?;
    } else {
        return Err(anyhow!("Missing file system image"));
    }

    Ok(())
}

pub fn gen_key(name: &str, path: &Path) -> Result<()> {
    let mut csprng = OsRng {};
    let key_pair = Keypair::generate(&mut csprng);
    let pub_key = path.join(name).with_extension("pub");
    let prv_key = path.join(name).with_extension("key");
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

fn read_manifest(src_path: &Path) -> Result<Manifest> {
    let manifest_path = src_path.join(MANIFEST_BASE).with_extension(&MANIFEST_EXT);
    let manifest = std::fs::File::open(&manifest_path)
        .with_context(|| format!("Failed to open '{}'", &manifest_path.display()))?;
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

fn read_keypair(key_file_path: &Path) -> Result<Keypair> {
    let mut secret_key_bytes = [0u8; SECRET_KEY_LENGTH];
    File::open(&key_file_path)
        .with_context(|| format!("Fail to open '{}'", &key_file_path.display()))?
        .read_exact(&mut secret_key_bytes)
        .with_context(|| {
            format!(
                "Failed to read key data from '{}'",
                &key_file_path.display()
            )
        })?;
    let secret_key = SecretKey::from_bytes(&secret_key_bytes).with_context(|| {
        format!(
            "Failed to derive secret key from '{}'",
            &key_file_path.display()
        )
    })?;
    let public_key = PublicKey::from(&secret_key);
    Ok(Keypair {
        secret: secret_key,
        public: public_key,
    })
}

fn gen_salt() -> [u8; SHA256_SIZE] {
    let mut salt = [0u8; SHA256_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

fn gen_hashes_yaml(
    tmp_manifest_path: &Path,
    fsimg_path: &Path,
    fsimg_size: u64,
    verity_hash: &[u8],
) -> Result<String> {
    // Create hashes YAML
    let mut sha256 = Sha256::new();
    io::copy(
        &mut File::open(&tmp_manifest_path)
            .with_context(|| format!("Failed to open '{}'", &tmp_manifest_path.display()))?,
        &mut sha256,
    )?;
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

fn gen_signature_yaml(
    key_file_path: &Path,
    fsimg_path: &Path,
    tmp_manifest_path: &Path,
) -> Result<String> {
    let fsimg_size = fs::metadata(&fsimg_path)
        .with_context(|| format!("Fail to read read size of '{}'", &fsimg_path.display()))?
        .len();
    let verity_hash = create_verity_header(&fsimg_path, fsimg_size)?;
    let key_pair = read_keypair(&key_file_path)?;
    let hashes_yaml = gen_hashes_yaml(&tmp_manifest_path, &fsimg_path, fsimg_size, &verity_hash)?;
    let signature_yaml = sign_hashes(&key_pair, &hashes_yaml);
    Ok(signature_yaml)
}

fn gen_pseudo_files(manifest: &Manifest) -> Result<Vec<(&str, u32)>> {
    let mut pseudo_files = vec![];
    if manifest.init.is_some() {
        pseudo_files = vec![("/dev", 444), ("/proc", 444), ("/tmp", 444)];
    }
    for mount in manifest.mounts.iter() {
        match mount {
            Mount::Resource { target, .. } => {
                /* In order to support mount points with multiple path segments, we need to call mksquashfs multiple times:
                 * e.gl to support res/foo in our image, we need to add /res/foo AND /res
                 * ==> mksquashfs ... -p "/res/foo d 444 1000 1000"  -p "/res d 444 1000 1000" */
                let trail = path_trail(&target);
                for path in trail {
                    pseudo_files.push((
                        path.as_os_str()
                            .to_str()
                            .with_context(|| "Cannot convert pseudo file path to string")?,
                        555,
                    ));
                }
            }
            Mount::Bind { target, flags, .. } | Mount::Persist { target, flags, .. } => {
                let mode = if flags.contains(&MountFlag::Rw) {
                    777
                } else {
                    444
                };
                pseudo_files.push((
                    target
                        .to_str()
                        .with_context(|| "Cannot convert manifest mount point to string")?,
                    mode,
                ));
            }
        }
    }
    Ok(pseudo_files)
}

fn gen_hash_tree(
    image: &File,
    image_size: u64,
    block_size: u64,
    salt: &[u8; SHA256_SIZE],
    hash_level_offsets: &[usize],
    tree_size: usize,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut hash_tree = vec![0_u8; tree_size];
    let hash_src_offset = 0;
    let mut hash_src_size = image_size;
    let mut level_num = 0;
    let mut reader = BufReader::new(image);
    let mut level_output: Vec<u8> = vec![];

    while hash_src_size > block_size {
        let mut level_output_list: Vec<[u8; SHA256_SIZE]> = vec![];
        let mut remaining = hash_src_size;
        while remaining > 0 {
            let mut sha256 = Sha256::new();
            sha256.update(salt);

            let data_len;
            if level_num == 0 {
                let offset = hash_src_offset + hash_src_size - remaining;
                data_len = std::cmp::min(remaining, block_size);
                let mut data = vec![0_u8; data_len as usize];
                reader.seek(Start(offset))?;
                reader.read_exact(&mut data)?;
                sha256.update(&data);
            } else {
                let offset =
                    hash_level_offsets[level_num - 1] + hash_src_size as usize - remaining as usize;
                data_len = block_size;
                sha256.update(&hash_tree[offset..offset + data_len as usize]);
            }

            remaining -= data_len;
            if data_len < block_size {
                let zeros = vec![0_u8; (block_size - data_len) as usize];
                sha256.update(zeros);
            }
            level_output_list.push(sha256.finalize().into());
        }

        level_output = level_output_list
            .iter()
            .flat_map(|s| s.iter().copied())
            .collect();
        let padding_needed =
            round_up_to_multiple(level_output.len(), block_size as usize) - level_output.len();
        level_output.append(&mut vec![0_u8; padding_needed]);

        let offset = hash_level_offsets[level_num];
        hash_tree[offset..offset + level_output.len()].copy_from_slice(level_output.as_slice());

        hash_src_size = level_output.len() as u64;
        level_num += 1;
    }

    let digest = Sha256::digest(
        &salt
            .iter()
            .copied()
            .chain(level_output.iter().copied())
            .collect::<Vec<u8>>(),
    );

    Ok((digest.to_vec(), hash_tree))
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

fn calc_hash_level_offsets(
    image_size: usize,
    block_size: usize,
    digest_size: usize,
) -> (Vec<usize>, usize) {
    let mut level_offsets: Vec<usize> = vec![];
    let mut level_sizes: Vec<usize> = vec![];
    let mut tree_size = 0;

    let mut num_levels = 0;
    let mut size = image_size;
    while size > block_size {
        let num_blocks = (size + block_size - 1) / block_size;
        let level_size = round_up_to_multiple(num_blocks * digest_size, block_size);

        level_sizes.push(level_size);
        tree_size += level_size;
        num_levels += 1;

        size = level_size;
    }

    for n in 0..num_levels {
        let mut offset = 0;
        #[allow(clippy::needless_range_loop)]
        for m in (n + 1)..num_levels {
            offset += level_sizes[m];
        }
        level_offsets.push(offset);
    }

    (level_offsets, tree_size)
}

fn copy_src_root_to_tmp(src_path: &Path, tmp: &TempDir) -> Result<PathBuf> {
    let src_root_path = src_path.join(&ROOT_DIR_NAME);
    let tmp_root_path = tmp.path().join(&ROOT_DIR_NAME);
    if src_root_path.exists() {
        fs_extra::dir::copy(&src_root_path, &tmp, &fs_extra::dir::CopyOptions::new())
            .with_context(|| {
                format!(
                    "Cannot copy from '{}' to '{}'",
                    &src_root_path.display(),
                    &tmp.path().display()
                )
            })?;
    } else {
        // create empty root dir at destination if we have nothing to copy
        fs_extra::dir::create(&tmp_root_path, false).with_context(|| {
            format!("Failed to create directory '{}'", &tmp_root_path.display())
        })?;
    }
    Ok(tmp_root_path)
}

fn create_fs_img(tmp_root_path: &Path, manifest: &Manifest, fsimg_path: &Path) -> Result<()> {
    let pseudo_files =
        gen_pseudo_files(&manifest).with_context(|| "Failed to generate list of pseudo files")?;
    create_squashfs(&tmp_root_path, &fsimg_path, &pseudo_files)
        .with_context(|| format!("Failed to create squashfs in '{}'", &fsimg_path.display()))?;
    Ok(())
}

fn create_verity_header(fsimg_path: &Path, fsimg_size: u64) -> Result<Vec<u8>> {
    let salt = gen_salt();
    let (hash_level_offsets, tree_size) =
        calc_hash_level_offsets(fsimg_size as usize, BLOCK_SIZE, SHA256_SIZE as usize);
    let (verity_hash, hash_tree) = gen_hash_tree(
        &File::open(&fsimg_path).with_context(|| format!("Cannot open '{}'", &FS_IMG_NAME))?,
        fsimg_size,
        BLOCK_SIZE as u64,
        &salt,
        &hash_level_offsets,
        tree_size,
    )
    .with_context(|| "Error while generating hash tree")?;
    write_verity_header(&fsimg_path, fsimg_size, &salt, &hash_tree)
        .with_context(|| "Error while writing verity header")?;
    Ok(verity_hash)
}

fn create_squashfs(
    tmp_root_path: &Path,
    fsimg_path: &Path,
    pseudo_dirs: &[(&str, u32)],
) -> Result<()> {
    #[cfg(target_os = "linux")]
    let compression_alg = "gzip";
    #[cfg(not(target_os = "linux"))]
    let compression_alg = "zstd";

    if which::which(&MKSQUASHFS_BIN).is_err() {
        return Err(anyhow!("Failed to find '{}'", &MKSQUASHFS_BIN));
    }
    let mut cmd = Command::new(&MKSQUASHFS_BIN);
    cmd.arg(tmp_root_path.as_os_str().to_str().with_context(|| {
        format!(
            "Failed to convert tmp root path '{}' to string",
            &tmp_root_path.display()
        )
    })?)
    .arg(fsimg_path.as_os_str().to_str().with_context(|| {
        format!(
            "Failed to convert '{}' path '{}' to string",
            &FS_IMG_NAME,
            &fsimg_path.display()
        )
    })?)
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

    if !fsimg_path.exists() {
        Err(anyhow!(
            "'{}' did not create '{}'",
            &MKSQUASHFS_BIN,
            &FS_IMG_NAME
        ))
    } else {
        Ok(())
    }
}

fn write_verity_header(
    fsimg_path: &Path,
    fsimg_size: u64,
    salt: &[u8; 32],
    hash_tree: &[u8],
) -> Result<()> {
    let uuid = Uuid::new_v4();
    assert_eq!(fsimg_size % BLOCK_SIZE as u64, 0);
    let data_blocks = fsimg_size / BLOCK_SIZE as u64;

    /* ['verity', 1, 1, uuid.gsub('-', ''), 'sha256', 4096, 4096, data_blocks, 32, salt, '']
     * .pack('a8 L L H32 a32 L L Q S x6 a256 a3752')
     * (https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMVerity#verity-superblock-format)
     * (https://ruby-doc.org/core-2.7.1/Array.html#method-i-pack) */
    let mut fsimg = OpenOptions::new()
        .write(true)
        .append(true)
        .open(&fsimg_path)
        .with_context(|| format!("Cannot open '{}'", &fsimg_path.display()))?;
    fsimg.write_all(b"verity")?;
    fsimg.write_all(&[0_u8, 0_u8])?;
    fsimg.write_all(&1_u32.to_ne_bytes())?;
    fsimg.write_all(&1_u32.to_ne_bytes())?;
    fsimg.write_all(&hex::decode(uuid.to_string().replace("-", ""))?)?;
    fsimg.write_all(b"sha256")?;
    fsimg.write_all(&[0_u8; 26])?;
    fsimg.write_all(&4096_u32.to_ne_bytes())?;
    fsimg.write_all(&4096_u32.to_ne_bytes())?;
    fsimg.write_all(&data_blocks.to_ne_bytes())?;
    fsimg.write_all(&32_u16.to_ne_bytes())?;
    fsimg.write_all(&[0_u8; 6])?;
    fsimg.write_all(&salt.to_vec())?;
    fsimg.write_all(&vec![0_u8; 256 - salt.len()])?;
    fsimg.write_all(&[0_u8; 3752])?;
    fsimg.write_all(&hash_tree)?;

    Ok(())
}

fn write_npk(
    out_path: &Path,
    manifest: &Manifest,
    fsimg_path: &Path,
    signature_yaml: &str,
) -> Result<()> {
    let npk_path = out_path
        .join(format!("{}-{}.", &manifest.name, &manifest.version))
        .with_extension(&NPK_EXT);
    let npk_file = File::create(&npk_path)
        .with_context(|| format!("Failed to create NPK at '{}'", &npk_path.display()))?;
    let zip_options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut zip_writer = zip::ZipWriter::new(&npk_file);
    zip_writer.start_file(SIGNATURE_NAME, zip_options)?;
    zip_writer.write_all(signature_yaml.as_bytes())?;
    zip_writer.start_file(MANIFEST_NAME, zip_options)?;
    let manifest_string = serde_yaml::to_string(&manifest)?;
    zip_writer.write_all(manifest_string.as_bytes())?;

    /* We need to ensure that the fs.img start at an offset of 4096 so we add empty (zeros) ZIP
     * 'extra data' to inflate the header of the ZIP file.
     * See chapter 4.3.6 of APPNOTE.TXT
     * (https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) */
    const ZIP_LOCAL_FILE_HEADER_LEN: usize = 30;
    let offset = (ZIP_LOCAL_FILE_HEADER_LEN + MANIFEST_NAME.len() + manifest_string.len())
        + (ZIP_LOCAL_FILE_HEADER_LEN + SIGNATURE_NAME.len() + signature_yaml.len())
        + (ZIP_LOCAL_FILE_HEADER_LEN + FS_IMG_NAME.len());
    let padding_len = (offset / BLOCK_SIZE + 1) * BLOCK_SIZE - offset;
    let zero_padding = vec![0_u8; padding_len];

    zip_writer.start_file_with_extra_data(FS_IMG_NAME, zip_options, &zero_padding)?;
    let mut fsimg = File::open(&fsimg_path)
        .with_context(|| format!("Failed to open '{}'", &fsimg_path.display()))?;
    let mut fsimg_cont: Vec<u8> = vec![0u8; fs::metadata(&fsimg_path)?.len() as usize];
    fsimg.read_exact(&mut fsimg_cont)?;
    zip_writer.write_all(&fsimg_cont)?;

    Ok(())
}

fn print_zip(zip_writer: &mut ZipArchive<&File>) -> Result<()> {
    for file_index in 0..zip_writer.len() {
        println!("{}", zip_writer.by_index(file_index)?.name());
    }
    println!();
    Ok(())
}

fn print_file(path: &Path) -> Result<()> {
    let mut file =
        File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    io::copy(&mut file, &mut io::stdout())?;
    println!();
    Ok(())
}

fn print_squashfs(fsimg_path: &Path) -> Result<()> {
    if which::which(&UNSQUASHFS_BIN).is_err() {
        return Err(anyhow!("Failed to find '{}'", &UNSQUASHFS_BIN));
    }
    let mut cmd = Command::new(&UNSQUASHFS_BIN);
    cmd.arg("-ll")
        .arg(fsimg_path.as_os_str().to_str().with_context(|| {
            format!(
                "Failed to convert '{}' path '{}' to string",
                &FS_IMG_NAME,
                &fsimg_path.display()
            )
        })?);
    let output = cmd
        .output()
        .with_context(|| format!("Error while executing '{}'", &UNSQUASHFS_BIN))?;
    println!(
        "{}",
        String::from_utf8(output.stdout)
            .with_context(|| format!("Cannot print '{}' output", &UNSQUASHFS_BIN))?
    );
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

fn create_tmp_dir() -> Result<TempDir> {
    TempDir::new("sextant").with_context(|| "Cannot create temporary directory")
}

fn assume_non_existing(path: &Path) -> Result<()> {
    if path.exists() {
        Err(anyhow!("File '{}' already exists", &path.display()))
    } else {
        Ok(())
    }
}

fn round_up_to_multiple(number: usize, factor: usize) -> usize {
    let round_down_to_multiple = number + factor - 1;
    round_down_to_multiple - (round_down_to_multiple % factor)
}
