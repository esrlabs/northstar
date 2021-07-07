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
use std::path::PathBuf;
use tempfile::TempDir;

pub const EXAMPLE_CPUEATER: &str = "cpueater:0.0.1";
pub const EXAMPLE_CRASHING: &str = "crashing:0.0.1";
pub const EXAMPLE_FERRIS: &str = "ferris:0.0.1";
pub const EXAMPLE_HELLO_FERRIS: &str = "hello-ferris:0.0.1";
pub const EXAMPLE_HELLO_RESOURCE: &str = "hello-resource:0.0.1";
pub const EXAMPLE_INSPECT: &str = "inspect:0.0.1";
pub const EXAMPLE_MEMEATER: &str = "memeater:0.0.1";
pub const EXAMPLE_MESSAGE_0_0_1: &str = "message:0.0.1";
pub const EXAMPLE_MESSAGE_0_0_2: &str = "message:0.0.2";
pub const EXAMPLE_PERSISTENCE: &str = "persistence:0.0.1";
pub const EXAMPLE_SECCOMP: &str = "seccomp:0.0.1";
pub const TEST_CONTAINER: &str = "test-container:0.0.1";
pub const TEST_RESOURCE: &str = "test-resource:0.0.1";

fn dump(src: &[u8]) -> PathBuf {
    let npk = TMPDIR.path().join(uuid::Uuid::new_v4().to_string());
    std::fs::write(&npk, src).expect("Failed to dump npk");
    npk
}

lazy_static! {
    static ref TMPDIR: TempDir = TempDir::new().expect("Failed to create tmpdir");
    pub static ref EXAMPLE_CRASHING_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/crashing-0.0.1.npk"));
        dump(src)
    };
    pub static ref EXAMPLE_CPUEATER_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/cpueater-0.0.1.npk"));
        dump(src)
    };
    pub static ref EXAMPLE_FERRIS_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/ferris-0.0.1.npk"));
        dump(src)
    };
    pub static ref EXAMPLE_HELLO_FERRIS_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/hello-ferris-0.0.1.npk"));
        dump(src)
    };
    pub static ref EXAMPLE_HELLO_RESOURCE_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/hello-resource-0.0.1.npk"));
        dump(src)
    };
    pub static ref EXAMPLE_INSPECT_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/inspect-0.0.1.npk"));
        dump(src)
    };
    pub static ref EXAMPLE_MEMEATER_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/memeater-0.0.1.npk"));
        dump(src)
    };
    pub static ref EXAMPLE_MESSAGE_0_0_1_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/message-0.0.1.npk"));
        dump(src)
    };
    pub static ref EXAMPLE_MESSAGE_0_0_2_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/message-0.0.2.npk"));
        dump(src)
    };
    pub static ref EXAMPLE_PERSISTENCE_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/persistence-0.0.1.npk"));
        dump(src)
    };
    pub static ref EXAMPLE_SECCOMP_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/seccomp-0.0.1.npk"));
        dump(src)
    };
    pub static ref TEST_CONTAINER_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/test-container-0.0.1.npk"));
        dump(src)
    };
    pub static ref TEST_RESOURCE_NPK: PathBuf = {
        let src = include_bytes!(concat!(env!("OUT_DIR"), "/test-resource-0.0.1.npk"));
        dump(src)
    };
}
