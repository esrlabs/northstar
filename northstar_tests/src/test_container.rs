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

use async_once::AsyncOnce;
use color_eyre::eyre::WrapErr;
use escargot::CargoBuild;
use lazy_static::lazy_static;
use log::debug;
use northstar::api::model::Container;
use npk::npk;
use std::{
    convert::TryInto,
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use tokio::fs;

pub const TEST_CONTAINER: &str = "test_container:0.0.1:test";
pub const TEST_RESOURCE: &str = "test_resource:0.0.1:test";
const MANIFEST: &str = "northstar_tests/test_container/Cargo.toml";

lazy_static! {
    static ref REPOSITORY: TempDir = TempDir::new().unwrap();
    static ref TEST_CONTAINER_NPK: AsyncOnce<PathBuf> = AsyncOnce::new(async {
        let package_dir = TempDir::new().unwrap();
        let root = package_dir.path().join("root");

        debug!("Building test container binary");
        let binary_path = CargoBuild::new()
            .manifest_path(MANIFEST)
            .run()
            .wrap_err("Failed to build the test_container")
            .unwrap()
            .path()
            .to_owned();

        debug!("Creating test container binary npk");
        fs::create_dir_all(&root).await.unwrap();

        async fn copy_file(file: &Path, dir: &Path) {
            assert!(file.is_file());
            assert!(dir.is_dir());
            let filename = file.file_name().unwrap();
            fs::copy(file, dir.join(filename)).await.unwrap();
        }

        copy_file(&binary_path, &root).await;
        copy_file(
            Path::new("northstar_tests/test_container/manifest.yaml"),
            package_dir.path(),
        )
        .await;

        npk::pack(
            package_dir
                .path()
                .join("manifest")
                .with_extension("yaml")
                .as_path(),
            package_dir.path().join("root").as_path(),
            REPOSITORY.path(),
            Some(Path::new("examples/keys/northstar.key")),
        )
        .await
        .unwrap();

        REPOSITORY.path().join("test_container-0.0.1.npk")
    });
    static ref TEST_RESOURCE_NPK: AsyncOnce<PathBuf> = AsyncOnce::new(async {
        npk::pack(
            Path::new("northstar_tests/test_resource/manifest.yaml"),
            Path::new("northstar_tests/test_resource/root"),
            REPOSITORY.path(),
            Some(Path::new("examples/keys/northstar.key")),
        )
        .await
        .unwrap();
        REPOSITORY.path().join("test_resource-0.0.1.npk")
    });
}

/// Path to the test container npk
pub async fn test_container_npk() -> &'static Path {
    &TEST_CONTAINER_NPK.get().await
}

/// Test container key
pub fn test_container() -> Container {
    TEST_CONTAINER.try_into().unwrap()
}

// Path to the test resource npk
pub async fn test_resource_npk() -> &'static Path {
    &TEST_RESOURCE_NPK.get().await
}
