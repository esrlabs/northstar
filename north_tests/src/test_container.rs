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

use color_eyre::eyre::WrapErr;
use escargot::CargoBuild;
use lazy_static::lazy_static;
use npk::npk;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

lazy_static! {
    static ref REPOSITORIES_DIR: TempDir = TempDir::new().unwrap();
    static ref TEST_CONTAINER_NPK: PathBuf = {
        let build_dir = TempDir::new().unwrap();
        let package_dir = TempDir::new().unwrap();
        let root = package_dir.path().join("root");

        let binary_path = CargoBuild::new()
            .manifest_path("north_tests/test_container/Cargo.toml")
            .target_dir(build_dir.path())
            .run()
            .wrap_err("Failed to build the test_container")
            .unwrap()
            .path()
            .to_owned();

        std::fs::create_dir_all(&root).unwrap();

        fn copy_file(file: &Path, dir: &Path) {
            assert!(file.is_file());
            assert!(dir.is_dir());
            let filename = file.file_name().unwrap();
            std::fs::copy(file, dir.join(filename)).unwrap();
        }

        copy_file(&binary_path, &root);
        copy_file(
            Path::new("north_tests/test_container/manifest.yaml"),
            package_dir.path(),
        );

        npk::pack(
            package_dir.path(),
            REPOSITORIES_DIR.path(),
            Path::new("examples/keys/north.key"),
        )
        .unwrap();
        REPOSITORIES_DIR.path().join("test_container-0.0.1.npk")
    };
    static ref TEST_RESOURCE_NPK: PathBuf = {
        npk::pack(
            Path::new("north_tests/test_resource"),
            REPOSITORIES_DIR.path(),
            Path::new("examples/keys/north.key"),
        )
        .unwrap();
        REPOSITORIES_DIR.path().join("test_resource-0.0.1.npk")
    };
}

pub fn get_test_container_npk() -> &'static Path {
    &TEST_CONTAINER_NPK
}

pub fn get_test_resource_npk() -> &'static Path {
    &TEST_RESOURCE_NPK
}
