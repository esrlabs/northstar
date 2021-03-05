// Copyright (c) 2019 - 2021 ESRLabs
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

use log::info;
use northstar::api::{
    self,
    model::{ExitStatus, Notification},
};
use northstar_tests::{
    logger,
    runtime::Northstar,
    test,
    test_container::{test_container, TEST_CONTAINER, TEST_RESOURCE},
};
use std::{convert::TryInto, path::PathBuf};

// Smoke test the integration test harness
test!(smoke, {
    let runtime = Northstar::launch().await?;
    runtime.install_test_container().await?;
    runtime.uninstall_test_container().await?;
    runtime.shutdown().await
});

// Install and uninstall is a loop. After a number of installation
// try to start the test container
test!(install_uninstall, {
    let runtime = Northstar::launch().await?;

    for _ in 0u32..30 {
        runtime.install_test_container().await?;
        runtime.uninstall_test_container().await?;
    }

    runtime.shutdown().await
});

// Start and stop a container multiple times
test!(start_stop, {
    let mut runtime = Northstar::launch().await?;

    runtime.install_test_container().await?;
    runtime.install_test_resource().await?;

    for i in 0..50 {
        info!("Iteration {}", i);
        runtime.start(TEST_CONTAINER).await?;
        logger::assume("Sleeping", 5u64).await?;
        runtime.stop(TEST_CONTAINER, 5).await?;
        runtime
            .assume_notification(move |n| n == &Notification::Stopped(test_container()), 5)
            .await?;
    }

    runtime.shutdown().await
});

// Start and stop a container without waiting
test!(start_stop_no_wait, {
    let runtime = Northstar::launch().await?;

    runtime.install_test_container().await?;
    runtime.install_test_resource().await?;

    for _ in 0..10 {
        runtime.start(TEST_CONTAINER).await?;
        runtime.stop(TEST_CONTAINER, 5).await?;
        logger::assume("Sending SIGTERM", 5u64).await?;
        logger::assume("exit code is 0", 5).await?;
        logger::assume("Stopped .* with status Exit\\(0\\)", 5).await?;
    }

    runtime.uninstall_test_container().await?;
    runtime.uninstall_test_resource().await?;

    runtime.shutdown().await
});

// Mount and umount all containers known to the runtime
test!(mount, {
    let runtime = Northstar::launch().await?;

    runtime.install_test_container().await?;
    runtime.install_test_resource().await?;

    let containers = &runtime.containers().await?;

    (*runtime)
        .mount(
            containers
                .iter()
                .map(|c| (c.container.name().as_str(), c.container.version())),
        )
        .await?;

    // Umount
    for c in containers.iter().filter(|c| c.mounted) {
        runtime
            .umount(&format!("{}:{}", c.container.name(), c.container.version()))
            .await?;
    }

    runtime.shutdown().await
});

// Try to stop a not started container and expect an Err
test!(invalid_stop, {
    let runtime = Northstar::launch().await?;
    let container = "foo:0.0.1:default";
    assert!(runtime.stop(container, 5).await.is_err());
    runtime.shutdown().await
});

// Try to start a container whic is not installed/known
test!(unknown_container_start, {
    let runtime = Northstar::launch().await?;
    let container = "unknown_application:0.0.12:asdf";
    assert!(runtime.start(container).await.is_err());
    runtime.shutdown().await
});

// Try to start a container where a dependecy is missing
test!(missing_resource, {
    let runtime = Northstar::launch().await?;
    runtime.install_test_container().await?;
    // The TEST_RESOURCE is not installed.
    assert!(runtime.start(TEST_CONTAINER).await.is_err());
    runtime.shutdown().await
});

// Start a container that uses a resource
test!(resource, {
    let runtime = Northstar::launch().await?;

    // Install test container & resource
    runtime.install_test_container().await?;
    runtime.install_test_resource().await?;

    runtime.test_cmds("cat /resource/hello").await;

    // Start the test_container process
    runtime.start(TEST_CONTAINER).await?;

    logger::assume("hello from test resource", 5).await?;

    // The container might have finished at this point
    runtime.stop(TEST_CONTAINER, 5).await?;

    runtime.uninstall_test_container().await?;
    runtime.uninstall_test_resource().await?;

    runtime.shutdown().await
});

// Try to uninstall a started container
test!(uninstall_started, {
    let runtime = Northstar::launch().await?;

    runtime.install_test_container().await?;
    runtime.install_test_resource().await?;

    runtime.start(TEST_CONTAINER).await?;
    logger::assume("test_container: Sleeping...", 5u64).await?;

    let result = runtime.uninstall_test_container().await;
    assert!(result.is_err());

    runtime.stop(TEST_CONTAINER, 5).await?;

    runtime.shutdown().await
});

test!(start_umount_resource_start, {
    let runtime = Northstar::launch().await?;

    runtime.install_test_container().await?;
    runtime.install_test_resource().await?;

    // Start a container that depends on a resource.
    runtime.start(TEST_CONTAINER).await?;
    logger::assume("test_container: Sleeping...", 5u64).await?;
    runtime.stop(TEST_CONTAINER, 5).await?;

    // Umount the resource and start the container again.
    runtime.umount(TEST_RESOURCE).await?;

    runtime.start(TEST_CONTAINER).await?;
    logger::assume("test_container: Sleeping...", 5u64).await?;

    runtime.stop(TEST_CONTAINER, 5).await?;

    runtime.shutdown().await
});

// The test is flaky and needs to listen for notifications
// in order to be implemented correctly
test!(crashing_container, {
    let mut runtime = Northstar::launch().await?;

    // install test container
    runtime.install_test_container().await?;
    runtime.install_test_resource().await?;

    for _ in 0..10 {
        runtime.test_cmds("crash").await;
        runtime.start(TEST_CONTAINER).await?;
        runtime
            .assume_notification(
                |n| {
                    n == &Notification::Exit {
                        container: TEST_CONTAINER.try_into().unwrap(),
                        status: ExitStatus::Exit(254),
                    }
                },
                15,
            )
            .await?;
    }

    runtime.uninstall_test_container().await?;
    runtime.uninstall_test_resource().await?;

    runtime.shutdown().await
});

// Check the uid/gid of a started container
test!(check_uid_and_gid, {
    let runtime = Northstar::launch().await?;

    runtime.install_test_container().await?;
    runtime.install_test_resource().await?;

    runtime.test_cmds("whoami").await;

    runtime.start(TEST_CONTAINER).await?;
    logger::assume("uid: 1000, gid: 1000", 5).await?;
    runtime.stop(TEST_CONTAINER, 5).await?;

    runtime.uninstall_test_container().await?;
    runtime.uninstall_test_resource().await?;

    runtime.shutdown().await
});

// Check whether after a runtime start, container start and shutdow
// any filedescriptor is leaked
test!(fd_leak, {
    /// Collect a set of files in /proc/$$/fd
    fn fds() -> Result<Vec<PathBuf>, std::io::Error> {
        let mut links = std::fs::read_dir("/proc/self/fd")?
            .filter_map(Result::ok)
            .flat_map(|entry| entry.path().read_link())
            .collect::<Vec<_>>();
        links.sort();
        Ok(links)
    }
    // Collect list of fds
    let before = fds()?;

    let runtime = Northstar::launch().await?;
    runtime.install_test_container().await?;
    runtime.install_test_resource().await?;

    runtime.start(TEST_CONTAINER).await?;
    logger::assume("test_container: Sleeping", 5u64).await?;
    runtime.stop(TEST_CONTAINER, 5).await?;

    let result = runtime.shutdown().await;

    // Compare the list of fds before and after the RT run.
    assert_eq!(before, fds()?);

    result
});

// Open many connections to the runtime
test!(connections, {
    let runtime = Northstar::launch().await?;

    let console = runtime.config().console.as_ref().unwrap();

    let mut clients = Vec::new();
    for _ in 0..10 {
        let client = api::client::Client::new(&console).await?;
        clients.push(client);
    }

    let result = runtime.shutdown().await;

    for client in &clients {
        assert!(client.containers().await.is_err());
    }
    clients.clear();

    result
});

// test!(cgroups_memory, {
//     let runtime = Northstar::launch().await?;

//     runtime.install_test_container().await?;
//     runtime.install_test_resource().await?;

//     runtime.test_cmds("leak-memory").await;

//     runtime.start(TEST_CONTAINER).await?;
//     logger::assume("Eating a Megabyte", 5).await?;

//     // TODO: Add assertion about the test_containers ooms

//     runtime.shutdown().await
// });
