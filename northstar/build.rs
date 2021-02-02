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

use std::env;
use vergen::{generate_cargo_keys, ConstantsFlags};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=hello_world/src/main.rs");
    println!("cargo:rerun-if-changed=hello_world/Cargo.toml");
    println!("cargo:rerun-if-changed=hello_world/manifest.yaml");
    let flags = ConstantsFlags::BUILD_TIMESTAMP
        | ConstantsFlags::TARGET_TRIPLE
        | ConstantsFlags::SHA_SHORT
        | ConstantsFlags::SEMVER_FROM_CARGO_PKG;
    generate_cargo_keys(flags).expect("Unable to generate the cargo keys!");

    package_hello_example();
}

pub fn package_hello_example() {
    use std::{fs, path::Path, process::Command};
    use tempfile::tempdir;

    let out_dir_var = env::var_os("OUT_DIR").unwrap();
    let out_dir_path = Path::new(&out_dir_var);
    let out_dir_string = out_dir_var.to_string_lossy();

    let args = ["build", "--release", "--target-dir", &out_dir_string];
    let mut cmd = Command::new("cargo");

    let pwd = env::var_os("PWD").unwrap();
    let hello_dir = Path::new(&pwd).join("northstar").join("hello_world");

    cmd.stdout(std::process::Stdio::piped())
        .current_dir(&hello_dir)
        .args(&args)
        .output()
        .expect("Could not execute cargo build in build.rs");
    let hello_example_manifest = hello_dir.join("manifest.yaml");
    let pack_tmp_dir =
        tempdir().expect("Could not create tmp dir for packaging hello_world container");
    let hello_exe_path = out_dir_path.join("release").join("hello_world");
    let root_dir = pack_tmp_dir.path().join("root");

    if !root_dir.exists() {
        fs::create_dir(&root_dir).expect("Could not create container root directory");
    }
    fs::copy(hello_exe_path, root_dir.join("hello_world"))
        .expect("Could not copy hello_world file");
    fs::copy(
        hello_example_manifest,
        pack_tmp_dir.path().join("manifest.yaml"),
    )
    .expect("Could not copy hello_world manifest file");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("northstar")
        .build()
        .expect("Creating tokio runtime failed");

    let squashfs_opts = npk::npk::SquashfsOpts {
        comp: None,
        block_size: None,
    };
    runtime
        .block_on(npk::npk::pack_with(
            &pack_tmp_dir.path(),
            &out_dir_path,
            None, // without a key
            squashfs_opts,
        ))
        .expect("Packaging the hello_world container failed");
}
