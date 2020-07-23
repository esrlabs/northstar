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

#![deny(clippy::all)]

use anyhow::{anyhow, Context, Error, Result};
use fs_extra::dir::{copy, CopyOptions};
use log::info;
use north_common::manifest::Manifest;
use rand::RngCore;
use serde_yaml;
use std::fs::File;
use std::path::Path;
use std::process::Command;
use std::{fs, path::PathBuf, str::FromStr};
use structopt::StructOpt;
use tempdir::TempDir;
use uuid::Uuid;

#[derive(Debug)]
enum Format {
    Text,
    Json,
}

impl FromStr for Format {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Format::Json),
            "text" | "txt" => Ok(Format::Text),
            _ => Err(anyhow!("Invalid format {}", s)),
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(about = "Northstar CLI")]
enum Opt {
    /// Pack Northstar containers
    Pack {
        /// Container source dir
        #[structopt(short, long)]
        dir: PathBuf,
        #[structopt(short, long)]
        out: PathBuf,
    },
    /// Unpack Northstar containers
    Unpack {
        /// Container source dir
        #[structopt(short, long)]
        dir: PathBuf,
        #[structopt(short, long)]
        out: PathBuf,
    },
    /// Print information about a Northstar container
    Inspect {
        /// Container to inspect
        #[structopt(short, long)]
        container: PathBuf,
        /// Output format
        #[structopt(short, long)]
        format: Format,
    },
}

// TODO: all from here: move to its own file

#[derive(PartialEq)]
enum FsType {
    SQUASHFS,
    EXT4,
}

fn pack_cmd(_dir: &Path, _out: &Path) -> Result<()> {
    let current_dir = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            log::debug!("{}", err.to_string());
            unimplemented!()
        }
    };
    let example_dir = current_dir.join("examples");
    let container_src_dir = example_dir.join("container");
    let key_dir = example_dir.join("keys");
    let registry_dir = current_dir.join("target").join("north").join("registry");

    pack_containers(
        &registry_dir,
        &container_src_dir,
        &key_dir,
        "north",
        &FsType::SQUASHFS,
        1000,
        1000,
    )
}

fn pack_containers(
    registry_dir: &Path,
    container_src_dir: &Path,
    key_dir: &Path,
    signing_key_name: &str,
    fs_type: &FsType,
    uid: u32,
    gid: u32,
) -> Result<()> {
    log::debug!("");
    log::debug!("pack_containers called with");
    log::debug!(
        "registry_dir={}",
        registry_dir.as_os_str().to_str().unwrap()
    );
    log::debug!(
        "container_src_dir={}",
        container_src_dir.as_os_str().to_str().unwrap()
    );
    log::debug!("key_dir={}", key_dir.as_os_str().to_str().unwrap());
    log::debug!("signing_key_name={}", signing_key_name);

    let sign_key_path = key_dir.join(signing_key_name).with_extension("key");
    log::debug!("open file {}", sign_key_path.as_os_str().to_str().unwrap());
    let sign_key = File::open(&sign_key_path)?;
    log::debug!("sign_key.len()={}", sign_key.metadata().unwrap().len());

    let mut src_dirs = fs::read_dir(container_src_dir)?
        .map(|res| res.map(|e| e.path()))
        .filter_map(Result::ok)
        .filter(|r| r.join("manifest.yaml").exists())
        .collect::<Vec<_>>();
    src_dirs.sort();
    for src_dir in src_dirs {
        pack(
            &src_dir,
            &registry_dir,
            &sign_key,
            &signing_key_name,
            &fs_type,
            uid,
            gid,
        )?;
    }

    Ok(())
}

fn pack(
    src_dir: &Path,
    registry_dir: &Path,
    signing_key: &File,
    signing_key_name: &str,
    fs_type: &FsType,
    uid: u32,
    gid: u32,
) -> Result<()> {
    log::debug!("");
    log::debug!("pack called with");
    log::debug!("src_dir={}", src_dir.display());
    log::debug!("registry_dir={}", registry_dir.display());
    log::debug!("signing_key_name={}", signing_key_name);

    // load manifest
    let manifest_file_path = src_dir.join("manifest").with_extension("yaml");
    let arch = "x86_64-unknown-linux-gnu"; // TODO: get as CLI parameter
    let manifest_file = std::fs::File::open(&manifest_file_path)?;
    log::debug!(
        "read manifest file {}",
        manifest_file_path.as_os_str().to_str().unwrap()
    );
    let manifest: Manifest = serde_yaml::from_reader(manifest_file)
        .with_context(|| format!("Failed to parse {}", manifest_file_path.display()))?;

    let tmp_dir = TempDir::new("")?;

    println!("find {}:", tmp_dir.path().as_os_str().to_str().unwrap());
    println!(
        "{}",
        String::from_utf8_lossy(
            &Command::new("find")
                .arg(tmp_dir.path().as_os_str().to_str().unwrap())
                .output()?
                .stdout
        )
    );

    // copy root
    log::debug!("copy root:");
    let root_dir = src_dir.join("root");
    let options = CopyOptions::new();
    let tmp_root_dir = tmp_dir.path().join("root");
    if root_dir.exists() {
        log::debug!(
            "copy {} to {}",
            root_dir.as_os_str().to_str().unwrap(),
            tmp_dir.path().as_os_str().to_str().unwrap()
        );
        copy(&root_dir, &tmp_dir, &options)?;
    }
    if !tmp_root_dir.exists() {
        log::debug!("mkdir {}", tmp_root_dir.as_os_str().to_str().unwrap());
        fs::create_dir(&tmp_root_dir)?;
    }

    println!("find {}:", tmp_dir.path().as_os_str().to_str().unwrap());
    println!(
        "{}",
        String::from_utf8_lossy(
            &Command::new("find")
                .arg(tmp_dir.path().as_os_str().to_str().unwrap())
                .output()?
                .stdout
        )
    );

    // copy arch specific root
    log::debug!("copy arch specific root:");
    let arch_dir = src_dir.join(format!("root-{}", arch));
    log::debug!("arch_dir={}", arch_dir.as_os_str().to_str().unwrap());
    if arch_dir.exists() {
        let arc_spec_files = fs::read_dir(arch_dir)?
            .map(|res| res.map(|e| e.path()))
            .filter_map(Result::ok)
            .collect::<Vec<PathBuf>>();
        log::debug!("arc_spec_dirs.len()={}", arc_spec_files.len());
        for arc_spec_file in arc_spec_files {
            log::debug!(
                "copy {} to {}",
                arc_spec_file.as_os_str().to_str().unwrap(),
                tmp_root_dir.as_os_str().to_str().unwrap()
            );
            // TODO: we assume copying a file and not a directory
            std::fs::copy(
                &arc_spec_file,
                &tmp_root_dir.join(arc_spec_file.file_name().unwrap()),
            )?;
            // fs_extra::dir::copy(&arc_spec_file, &tmp_root_dir, &options)?;
        }
    }

    println!("find {}:", tmp_dir.path().as_os_str().to_str().unwrap());
    println!(
        "{}",
        String::from_utf8_lossy(
            &Command::new("find")
                .arg(tmp_dir.path().as_os_str().to_str().unwrap())
                .output()?
                .stdout
        )
    );

    // write manifest
    log::debug!("write manifest");
    let tmp_manifest_dir = tmp_dir.path().join("manifest").with_extension("yaml");
    log::debug!(
        "create file {}",
        tmp_manifest_dir.as_os_str().to_str().unwrap()
    );
    let tmp_manifest_file = File::create(&tmp_manifest_dir)?;
    log::debug!(
        "writing file {}",
        tmp_manifest_dir.as_os_str().to_str().unwrap()
    );
    serde_yaml::to_writer(tmp_manifest_file, &manifest)?;

    // remove existing containers
    // TODO: remove all {registry}/#{name}-#{arch}-* directories

    let npk_dir = registry_dir
        .join(format!("{}-{}-{}", manifest.name, arch, manifest.version))
        .with_extension("npk");
    let fsimg_path = &tmp_dir.path().join("fs").with_extension("img");

    /* The list of pseudo files is target specific.
     * Add /lib and lib64 on Linux systems.
     * Add /system on Android. */
    let mut pseudo_files = vec![
        ("/tmp", 444),
        ("/proc", 444),
        ("/dev", 444),
        ("/sys", 444),
        ("/data", 777),
    ];
    if arch == "aarch64-unknown-linux-gnu" || arch == "x86_64-unknown-linux-gnu" {
        pseudo_files.push(("/lib", 444));
        pseudo_files.push(("/lib64", 444));
    } else if arch == "aarch64-linux-android" {
        pseudo_files.push(("/system", 444));
    }

    // create filesystem image
    let squashfs_comp = match std::env::consts::OS {
        "linux" => "gzip",
        _ => "zstd",
    };
    if fs_type == &FsType::SQUASHFS {
        let mut cmd = Command::new("mksquashfs");
        cmd.arg(tmp_root_dir.as_os_str().to_str().unwrap())
            .arg(fsimg_path.as_os_str().to_str().unwrap())
            .arg("-all-root")
            .arg("-comp")
            .arg(squashfs_comp)
            .arg("-no-progress")
            .arg("-info");
        for pseudo_file in pseudo_files {
            cmd.arg("-p");
            cmd.arg(format!(
                "{} d {} {} {}",
                pseudo_file.0,
                pseudo_file.1.to_string(),
                uid,
                gid
            ));
        }
        dbg!(&cmd);
        let cmd_output = cmd.output()?;
        println!("status={}", cmd_output.status);
        println!("stdout={}", String::from_utf8_lossy(&cmd_output.stdout));
        println!("stderr={}", String::from_utf8_lossy(&cmd_output.stderr));
    } else if fs_type == &FsType::EXT4 {
        unimplemented!()
    } else {
        unimplemented!() // unknown file type
    }
    println!("fsimg_path={}", fsimg_path.as_os_str().to_str().unwrap());
    let filesystem_size = fs::metadata(fsimg_path)?.len();

    // append verity header and hash tree to filesystem image
    const DIGEST_SIZE: usize = 32;
    const BLOCK_SIZE: u64 = 4096;
    assert_eq!(filesystem_size % BLOCK_SIZE, 0);
    let data_blocks = filesystem_size / BLOCK_SIZE;
    let uuid = Uuid::new_v4();
    let mut salt = [0u8; DIGEST_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    println!("filesystem_size={}", filesystem_size);
    println!("BLOCK_SIZE={}", BLOCK_SIZE);
    println!("DIGEST_SIZE={}", DIGEST_SIZE);
    let (hash_level_offsets, tree_size) = calc_hash_level_offsets(
        filesystem_size as usize,
        BLOCK_SIZE as usize,
        DIGEST_SIZE as usize,
    );
    println!("tree_size={}", tree_size);
    println!("hash_level_offsets.len()={}", hash_level_offsets.len());
    for hash_level_offset in hash_level_offsets {
        println!("hash_level_offset={}", hash_level_offset);
    }

    // create hashes YAML

    Ok(())
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
        num_levels = num_levels + 1;

        size = level_size;
    }

    for n in 0..num_levels {
        let mut offset = 0;
        for m in (n + 1)..num_levels {
            offset += level_sizes[m];
        }
        level_offsets.push(offset);
    }

    (level_offsets, tree_size)
}

// TODO
/*fn generate_hash_tree(image, image_size, block_size, salt, hash_level_offsets, tree_size)
{

}*/

fn round_up_to_multiple(number: usize, factor: usize) -> usize {
    let round_down = (number + factor - 1);
    round_down - (round_down % factor)
}

fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::from_args();
    info!("{:#?}", opt);
    match opt {
        Opt::Pack { dir, out } => pack_cmd(&dir, &out),
        _ => {
            unimplemented!();
        }
    }
}
