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

use anyhow::{Context, Result};
use escargot::CargoBuild;
use npk::manifest::Manifest;
use std::{env, fs, io::BufReader, path::Path};

const CARGO_MANIFEST: &str = "test_container/Cargo.toml";
const TEST_CONTAINER_MANIFEST: &str = "test_container/manifest.yaml";
const TEST_RESOURCE_MANIFEST: &str = "test_resource/manifest.yaml";
const KEY: &str = "../examples/keys/northstar.key";

fn load_manifest<P: AsRef<Path>>(path: P) -> Result<Manifest> {
    let manifest = fs::File::open(&path).context(format!(
        "Failed to open manifest file {}",
        path.as_ref().display()
    ))?;
    let reader = BufReader::new(manifest);
    serde_yaml::from_reader(reader).context("Failed to deserialize Manifest from file content")
}

fn main() {
    let tmpdir = tempfile::TempDir::new().expect("Failed to create tmpdir");
    let npk = tmpdir.path().join("npk");
    let root = npk.join("root");
    fs::create_dir_all(&root).expect("Failed to create npk root");

    // Build the test container binary
    let bin = CargoBuild::new()
        .manifest_path(CARGO_MANIFEST)
        .current_release()
        .target(env::var("TARGET").unwrap())
        .target_dir("target")
        .run()
        .expect("Failed to build")
        .path()
        .to_owned();
    fs::copy(&bin, &root.join("test_container")).expect("failed to copy bin");

    let out_dir = env::var("OUT_DIR").unwrap();

    let container_manifest = load_manifest(TEST_CONTAINER_MANIFEST).unwrap();
    let resource_manifest = load_manifest(TEST_RESOURCE_MANIFEST).unwrap();

    // Pack test container npk
    npk::npk::pack(
        container_manifest,
        npk.join("root"),
        Path::new(&out_dir),
        Some(Path::new(KEY)),
    )
    .expect("Failed to create test container npk");

    // Pack test resource npk
    npk::npk::pack(
        resource_manifest,
        &Path::new("test_resource").join("root"),
        Path::new(&out_dir),
        Some(Path::new(KEY)),
    )
    .expect("Failed to create test resource npk");
}
