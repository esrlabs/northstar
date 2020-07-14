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
use serde_yaml;
use serde_yaml::Value;
use std::fs::File;
use std::path::Path;
use std::{fs, path::PathBuf, str::FromStr};
use structopt::StructOpt;
use tempdir::TempDir;

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

    let tmp_dir = TempDir::new("tmp")?;

    // copy root
    log::debug!("copy root");
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
        fs::create_dir(&tmp_root_dir);
    }

    // copy arch specific root
    log::debug!("copy arch specific root");
    let arch_dir = src_dir.join(format!("root-{}", arch));
    log::debug!("arch_dir={}", arch_dir.as_os_str().to_str().unwrap());
    if arch_dir.exists() {
        let mut arc_spec_dirs = fs::read_dir(arch_dir)?
            .map(|res| res.map(|e| e.path()))
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        log::debug!("arc_spec_dirs.len()={}", arc_spec_dirs.len());
        for arc_spec_dir in arc_spec_dirs {
            log::debug!(
                "copy {} to {}",
                arc_spec_dir.as_os_str().to_str().unwrap(),
                tmp_root_dir.as_os_str().to_str().unwrap()
            );
        }
    }

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
    serde_yaml::to_writer(tmp_manifest_file, &manifest);

    // remove existing containers
    // TODO: remove all {registry}/#{name}-#{arch}-* directories

    // pack npk
    let npk_dir = registry_dir
        .join(format!("{}-{}-{}", manifest.name, arch, manifest.version))
        .with_extension("npk");
    let fsimg_path = tmp_dir.path().join("/fs").with_extension("img");
    log::debug!("npk_dir={}", npk_dir.into_os_string().to_str().unwrap());
    log::debug!(
        "fsimg_path={}",
        fsimg_path.into_os_string().to_str().unwrap()
    );

    // TODO: create NPK
    /* The list of pseudofiles is target specific.
     * Add /lib and lib64 on Linux systems.
     * Add /system on Android. */

    // TODO: create filesystem image
    // TODO: append verity header and hash tree to filesystem image
    // TODO: create hashes YAML

    Ok(())
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
