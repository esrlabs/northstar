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

use color_eyre::eyre::{eyre, Result};
use north::{api, api::Response};
use north_tests::{
    config::default_config,
    logger::wait_for_log_pattern,
    process_assert::ProcessAssert,
    runtime::Runtime,
    test,
    test_container::{get_test_container_npk, get_test_resource_npk},
};
use std::{path::Path, time::Duration};
use tokio::fs;

test!(hello, {
    let mut runtime = Runtime::launch(default_config().clone()).await.unwrap();
    runtime.start("hello").await?;
    let hello = runtime.pid("hello").await.map(ProcessAssert::new)?;

    // Here goes some kind of health check for the spawned process
    assert!(hello.is_running().await?);

    runtime.stop("hello").await?;
    runtime.shutdown().await?;
    Ok(())
});

test!(cpueater, {
    let mut runtime = Runtime::launch(default_config().clone()).await.unwrap();
    runtime.start("cpueater").await?;
    let cpueater = runtime.pid("cpueater").await.map(ProcessAssert::new)?;

    assert!(cpueater.is_running().await?);
    assert_eq!(cpueater.get_cpu_shares().await?, 100);

    runtime.stop("cpueater").await?;
    runtime.shutdown().await?;
    Ok(())
});

test!(memeater, {
    let mut runtime = Runtime::launch(default_config().clone()).await.unwrap();
    runtime.start("memeater").await?;
    let memeater = runtime.pid("memeater").await.map(ProcessAssert::new)?;

    assert!(memeater.is_running().await?);

    // NOTE
    // The limit in bytes indicated in the memory cgroup wont necessary be equal to the one
    // requested exactly. The kernel will assign some value close to it. For this reason we check
    // here that the limit assigned is greater than zero.
    assert!(memeater.get_limit_in_bytes().await? > 0);

    runtime.stop("memeater").await?;
    runtime.shutdown().await?;
    Ok(())
});

test!(start_unknown_application, {
    let mut runtime = Runtime::launch(default_config().clone()).await.unwrap();

    // Expect MissingResource Error
    match runtime.start("unknown_application").await? {
        Response::Err(api::Error::ApplicationNotFound) => Ok(()),
        _ => Err(eyre!("Starting unknown application did not fail")),
    }?;

    runtime.shutdown().await?;
    Ok(())
});

test!(missing_resource_container, {
    let mut runtime = Runtime::launch(default_config().clone()).await.unwrap();

    // install test container without resource
    runtime.install(get_test_container_npk()).await?;

    // Expect MissingResource Error
    match runtime.start("test_container-000").await? {
        Response::Err(api::Error::MissingResource(_)) => Ok(()),
        _ => Err(eyre!("Starting container without resurce did not fail")),
    }?;

    runtime.uninstall("test_container", "0.0.1").await?;

    runtime.shutdown().await?;
    Ok(())
});

test!(data_and_resource_mounts, {
    let mut runtime = Runtime::launch(default_config().clone()).await.unwrap();

    // install test container & resource
    runtime.install(get_test_resource_npk()).await?;
    runtime.install(get_test_container_npk()).await?;

    let data_dir = Path::new("target/north/data/test_container-000");
    fs::create_dir_all(&data_dir).await?;

    let input_file = data_dir.join("input.txt");

    // Write the input to the test_container
    fs::write(&input_file, b"cat /resource/hello").await?;

    // Start the test_container process
    runtime.start("test_container-000").await?;

    wait_for_log_pattern("hello from test resource", Duration::from_secs(5)).await?;

    runtime.stop("test_container-000").await?;

    // Remove the temporary data directory
    fs::remove_dir_all(&data_dir).await?;

    runtime.uninstall("test_container", "0.0.1").await?;
    runtime.uninstall("test_resource", "0.0.1").await?;

    runtime.shutdown().await?;
    Ok(())
});

test!(crashing_containers, {
    let mut runtime = Runtime::launch(default_config().clone()).await.unwrap();

    let data_dir = Path::new("target/north/data/").canonicalize()?;

    // install test container
    runtime.install(get_test_resource_npk()).await?;
    runtime.install(get_test_container_npk()).await?;

    for i in 0..5 {
        let dir = data_dir.join(format!("test_container-{:03}", i));
        fs::create_dir_all(&dir).await?;
        fs::write(dir.join("input.txt"), b"crash").await?;

        // Start the test_container process
        runtime.start(&format!("test_container-{:03}", i)).await?;
    }

    // Try to stop the containers before issuing the shutdown
    for i in 0..5 {
        runtime.stop(&format!("test_container-{:03}", i)).await?;
    }

    runtime.uninstall("test_container", "0.0.1").await?;
    runtime.uninstall("test_resource", "0.0.1").await?;

    runtime.shutdown().await
});
