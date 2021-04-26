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

use lazy_static::lazy_static;
use northstar::api::model::Container;
use std::{
    convert::TryInto,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

lazy_static! {
    static ref TMPDIR: TempDir = TempDir::new().expect("Failed to create tmpdir");
    static ref TEST_CONTAINER_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/test_container-0.0.1.npk"));
        let npk = TMPDIR.path().join("test-container.npk");
        std::fs::write(&npk, src).expect("Failed to dump npk");
        npk
    };
    static ref TEST_RESOURCE_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/test_resource-0.0.1.npk"));
        let npk = TMPDIR.path().join("test-resource.npk");
        std::fs::write(&npk, src).expect("Failed to dump npk");
        npk
    };
}

pub const TEST_CONTAINER: &str = "test_container:0.0.1:test";
pub const TEST_RESOURCE: &str = "test_resource:0.0.1:test";

/// Path to the test container npk
pub async fn test_container_npk() -> &'static Path {
    &TEST_CONTAINER_NPK
}

/// Test container key
pub fn test_container() -> Container {
    TEST_CONTAINER.try_into().unwrap()
}

// Path to the test resource npk
pub async fn test_resource_npk() -> &'static Path {
    &TEST_RESOURCE_NPK
}
