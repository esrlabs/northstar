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

use color_eyre::eyre::{Result, WrapErr};
use escargot::CargoBuild;
use lazy_static::lazy_static;
use north_tests::runtime::Runtime;
use npk::npk;
use std::{
    path::{Path, PathBuf},
    sync::Once,
};
use tempfile::TempDir;
use tokio::fs;

static INIT: Once = Once::new();

fn init() {
    INIT.call_once(|| {
        color_eyre::install().unwrap();
        env_logger::builder().is_test(true).try_init().ok();
    })
}

lazy_static! {
    static ref REPOSITORIES_DIR: TempDir = TempDir::new().unwrap();
    static ref TEST_CONTAINER_NPK: PathBuf = {
        let build_dir = TempDir::new().unwrap();
        let package_dir = TempDir::new().unwrap();
        let root = package_dir.path().join("root");

        let binary_path = CargoBuild::new()
            .manifest_path("test_container/Cargo.toml")
            .target_dir(build_dir.path())
            .run()
            .unwrap()
            .path()
            .to_owned();

        std::fs::create_dir_all(&root).unwrap();
        copy_file(&binary_path, &root);
        copy_file(
            Path::new("test_container/manifest.yaml"),
            package_dir.path(),
        );

        npk::pack(
            package_dir.path(),
            REPOSITORIES_DIR.path(),
            Path::new("../examples/keys/north.key"),
        )
        .unwrap();
        REPOSITORIES_DIR.path().join("test_container-0.0.1.npk")
    };
    static ref TEST_RESOURCE_NPK: PathBuf = {
        npk::pack(
            Path::new("test_resource"),
            REPOSITORIES_DIR.path(),
            Path::new("../examples/keys/north.key"),
        )
        .unwrap();
        REPOSITORIES_DIR.path().join("test_resource-0.0.1.npk")
    };
}

fn copy_file(file: &Path, dir: &Path) {
    assert!(file.is_file());
    assert!(dir.is_dir());
    let filename = file.file_name().unwrap();
    std::fs::copy(file, dir.join(filename)).unwrap();
}

#[ignore]
#[tokio::test]
async fn check_hello() -> Result<()> {
    init();
    let mut runtime = Runtime::launch().await?;

    let hello = runtime.start("hello").await?;

    // Here goes some kind of health check for the spawned process
    assert!(hello.is_running().await?);

    runtime.stop("hello").await?;
    runtime.shutdown().await
}

#[ignore]
#[tokio::test]
async fn check_cpueater() -> Result<()> {
    init();
    let mut runtime = Runtime::launch().await?;

    let cpueater = runtime.start("cpueater").await?;

    // Here goes some kind of health check for the spawned process
    assert_eq!(cpueater.get_cpu_shares().await?, 100);
    assert!(cpueater.is_running().await?);

    // Stop the cpueater process
    runtime.stop("cpueater").await?;
    runtime.shutdown().await
}

#[ignore]
#[tokio::test]
async fn check_memeater() -> Result<()> {
    init();

    let mut runtime = Runtime::launch().await?;

    let memeater = runtime.start("memeater").await?;

    // Here goes some kind of health check for the spawned process
    assert!(memeater.is_running().await?);

    // NOTE
    // The limit in bytes indicated in the memory cgroup wont necessary be equal to the one
    // requested exactly. The kernel will assign some value close to it. For this reason we check
    // here that the limit assigned is greater than zero.
    assert!(memeater.get_limit_in_bytes().await? > 0);

    // stop the memeater process
    runtime.stop("memeater").await?;
    runtime.shutdown().await
}

#[ignore]
#[tokio::test]
async fn check_data_and_resource_mount() -> Result<()> {
    init();

    let mut runtime = Runtime::launch().await?;

    // install test container & resource
    runtime.install(TEST_RESOURCE_NPK.as_path()).await?;
    runtime.install(TEST_CONTAINER_NPK.as_path()).await?;

    let data_dir = Path::new("../target/north/data/test_container-000");
    fs::create_dir_all(&data_dir).await?;

    let input_file = data_dir.join("input.txt");

    // Write the input to the test_container
    fs::write(&input_file, b"cat /resource/hello").await?;

    // // Start the test_container process
    runtime.start("test_container-000").await.map(drop)?;

    runtime
        .expect_output("hello from test resource")
        .await
        .wrap_err("Failed to read text from resource container")?;

    runtime.try_stop("test_container-000").await?;

    // Remove the temporary data directory
    fs::remove_dir_all(&data_dir).await?;

    for i in 0..5 {
        runtime
            .uninstall(&format!("test_container-0{:02}", i), "0.0.1")
            .await?;
    }
    runtime.uninstall("test_resource", "0.0.1").await?;

    runtime.shutdown().await
}

#[ignore]
#[tokio::test]
async fn check_crashing_container() -> Result<()> {
    init();

    let data_dir = Path::new("../target/north/data/").canonicalize()?;

    let mut runtime = Runtime::launch().await?;

    // install test container
    runtime.install(TEST_RESOURCE_NPK.as_path()).await?;
    runtime.install(&TEST_CONTAINER_NPK.as_path()).await?;

    for i in 0..5 {
        let dir = data_dir.join(format!("test_container-0{:02}", i));
        fs::create_dir_all(&dir).await?;
        fs::write(dir.join("input.txt"), b"crash").await?;

        // Start the test_container process
        runtime
            .start(&format!("test_container-0{:02}", i))
            .await
            .map(drop)?;
    }

    // Try to stop the containers before issuing the shutdown
    for i in 0..5 {
        runtime
            .try_stop(&format!("test_container-0{:02}", i))
            .await?;
    }

    for i in 0..5 {
        runtime
            .uninstall(&format!("test_container-0{:02}", i), "0.0.1")
            .await?;
    }
    runtime.uninstall("test_resource", "0.0.1").await?;

    runtime.shutdown().await
}
