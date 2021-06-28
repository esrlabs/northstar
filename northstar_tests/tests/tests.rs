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

use anyhow::Result;
use futures::{SinkExt, StreamExt};
use log::debug;
use logger::assume;
use northstar::api::{
    self,
    model::{self, ConnectNack, ExitStatus, Notification},
};
use northstar_tests::{
    logger,
    runtime::Northstar,
    test,
    test_container::{TEST_CONTAINER, TEST_RESOURCE},
};
use std::path::PathBuf;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UnixStream,
    time,
};

// Test a good and bad log assumption
test!(logger_smoketest, {
    debug!("Yippie");
    assume("Yippie", 3).await?;
    assert!(assume("Juhuuu!", 1).await.is_err());
    Result::<()>::Ok(())
});

// Smoke test the runtime startup and shutdown
test!(runtime_launch, {
    Northstar::launch().await?.shutdown().await
});

// Start the internal compiled in hello_world example
test!(internal_hello_world, {
    let runtime = Northstar::launch().await?;
    runtime.start("hello-world:0.0.1").await?;
    runtime.shutdown().await
});

// Install and uninstall is a loop. After a number of installation
// try to start the test container
test!(install_uninstall_test_container, {
    let runtime = Northstar::launch().await?;
    for _ in 0u32..10 {
        runtime.install_test_container().await?;
        runtime.uninstall_test_container().await?;
    }
    runtime.shutdown().await
});

// Start and stop a container multiple times
test!(start_stop_test_container_with_waiting, {
    let mut runtime = Northstar::launch_install_test_container().await?;

    for _ in 0..10u32 {
        runtime.start(TEST_CONTAINER).await?;
        assume("Sleeping", 5u64).await?;
        runtime.stop(TEST_CONTAINER, 5).await?;

        assume(
            "Stopped test_container:0.0.1 with status Signaled\\(SIGTERM\\)",
            5,
        )
        .await?;
        runtime
            .assume_notification(
                move |n| {
                    n == &Notification::Stopped(northstar_tests::test_container::test_container())
                },
                5,
            )
            .await?;
    }

    runtime.shutdown().await
});

// Start and stop a container without waiting
test!(start_stop_test_container_without_waiting, {
    let mut runtime = Northstar::launch_install_test_container().await?;

    for _ in 0..10u32 {
        runtime.start(TEST_CONTAINER).await?;
        runtime.stop(TEST_CONTAINER, 1).await?;

        assume(
            "Stopped test_container:0.0.1 with status Signaled\\(SIGTERM\\)",
            5,
        )
        .await?;
        runtime
            .assume_notification(
                move |n| {
                    n == &Notification::Stopped(northstar_tests::test_container::test_container())
                },
                5,
            )
            .await?;
    }
    runtime.shutdown().await
});

// Mount and umount all containers known to the runtime
test!(mount_umount_test_container_via_client, {
    let runtime = Northstar::launch_install_test_container().await?;

    // Mount
    let containers = &runtime.containers().await?;
    let containers = containers
        .iter()
        .map(|c| (c.container.name().as_str(), c.container.version()));
    (*runtime).mount(containers).await?;

    // Umount
    let containers = &runtime.containers().await?;
    for c in containers.iter().filter(|c| c.mounted) {
        let container = format!("{}:{}", c.container.name(), c.container.version());
        runtime.umount(&container).await?;
    }

    runtime.shutdown().await
});

// Try to stop a not started container and expect an Err
test!(try_to_stop_unknown_container, {
    let runtime = Northstar::launch().await?;
    let container = "foo:0.0.1:default";
    assert!(runtime.stop(container, 5).await.is_err());
    runtime.shutdown().await
});

// Try to start a container which is not installed/known
test!(try_to_start_unknown_container, {
    let runtime = Northstar::launch().await?;
    let container = "unknown_application:0.0.12:asdf";
    assert!(runtime.start(container).await.is_err());
    runtime.shutdown().await
});

// Try to start a container where a dependecy is missing
test!(try_to_start_containter_that_misses_a_resource, {
    let runtime = Northstar::launch().await?;
    runtime.install_test_container().await?;
    // The TEST_RESOURCE is not installed.
    assert!(runtime.start(TEST_CONTAINER).await.is_err());
    runtime.shutdown().await
});

// Start a container that uses a resource
test!(check_test_container_resource_usage, {
    let runtime = Northstar::launch().await?;

    // Install test container & resource
    runtime.install_test_container().await?;
    runtime.install_test_resource().await?;

    runtime.test_cmds("cat /resource/hello").await;

    // Start the test_container process
    runtime.start(TEST_CONTAINER).await?;

    assume("hello from test resource", 5).await?;

    // The container might have finished at this point
    runtime.stop(TEST_CONTAINER, 5).await?;

    runtime.uninstall_test_container().await?;
    runtime.uninstall_test_resource().await?;

    runtime.shutdown().await
});

// Try to uninstall a started container
test!(try_to_uninstall_a_started_container, {
    let runtime = Northstar::launch().await?;

    runtime.install_test_container().await?;
    runtime.install_test_resource().await?;

    runtime.start(TEST_CONTAINER).await?;
    assume("test_container: Sleeping...", 5u64).await?;

    let result = runtime.uninstall_test_container().await;
    assert!(result.is_err());

    runtime.stop(TEST_CONTAINER, 5).await?;

    runtime.shutdown().await
});

test!(start_mounted_container_with_not_mounted_resource, {
    let runtime = Northstar::launch().await?;

    runtime.install_test_container().await?;
    runtime.install_test_resource().await?;

    // Start a container that depends on a resource.
    runtime.start(TEST_CONTAINER).await?;
    assume("test_container: Sleeping...", 5u64).await?;
    runtime.stop(TEST_CONTAINER, 5).await?;

    // Umount the resource and start the container again.
    runtime.umount(TEST_RESOURCE).await?;

    runtime.start(TEST_CONTAINER).await?;
    assume("test_container: Sleeping...", 5u64).await?;

    runtime.stop(TEST_CONTAINER, 5).await?;

    runtime.shutdown().await
});

// The test is flaky and needs to listen for notifications
// in order to be implemented correctly
test!(container_crash_exit, {
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
                    matches!(
                        n,
                        Notification::Exit {
                            status: ExitStatus::Signaled(6),
                            ..
                        }
                    )
                },
                15,
            )
            .await?;
    }

    runtime.uninstall_test_container().await?;
    runtime.uninstall_test_resource().await?;

    runtime.shutdown().await
});

// Check uid. In the manifest of the test container the uid
// is set to 1000
test!(container_uses_correct_uid, {
    let runtime = Northstar::launch_install_test_container().await?;
    runtime.test_cmds("inspect").await;
    runtime.start(TEST_CONTAINER).await?;
    assume("getuid: 1000", 5).await?;
    runtime.shutdown().await
});

// Check gid. In the manifest of the test container the gid
// is set to 1000
test!(container_uses_correct_gid, {
    let runtime = Northstar::launch_install_test_container().await?;
    runtime.test_cmds("inspect").await;
    runtime.start(TEST_CONTAINER).await?;
    assume("getuid: 1000", 5).await?;
    runtime.shutdown().await
});

// Check parent pid. Northstar starts an init process which must have pid 1.
test!(container_ppid_must_be_init, {
    let runtime = Northstar::launch_install_test_container().await?;
    runtime.test_cmds("inspect").await;
    runtime.start(TEST_CONTAINER).await?;
    assume("getppid: 1", 5).await?;
    runtime.shutdown().await
});

// Check session id which needs to be pid of init
test!(container_sid_must_be_init_or_none, {
    let runtime = Northstar::launch_install_test_container().await?;
    runtime.test_cmds("inspect").await;
    runtime.start(TEST_CONTAINER).await?;

    assume("getsid: 1", 5).await?;

    runtime.shutdown().await
});

// The test container only gets the cap_kill capability. See the manifest
test!(container_shall_only_have_configured_capabilities, {
    let runtime = Northstar::launch_install_test_container().await?;
    runtime.test_cmds("inspect").await;
    runtime.start(TEST_CONTAINER).await?;
    assume("caps bounding: \\{CAP_KILL\\}", 5).await?;
    assume("caps effective: \\{CAP_KILL\\}", 5).await?;
    assume("caps permitted: \\{CAP_KILL\\}", 5).await?;
    runtime.shutdown().await
});

// Check whether after a runtime start, container start and shutdow
// any filedescriptor is leaked
test!(
    start_stop_runtime_and_containers_shall_not_leak_file_descriptors,
    {
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

        let runtime = Northstar::launch_install_test_container().await?;

        runtime.start(TEST_CONTAINER).await?;
        assume("test_container: Sleeping", 5).await?;
        runtime.stop(TEST_CONTAINER, 5).await?;

        let result = runtime.shutdown().await;

        // Compare the list of fds before and after the RT run.
        assert_eq!(before, fds()?);

        result
    }
);

// Check open file descriptors in the test container that should be
// stdin: /dev/null
// stdout: some pipe
// stderr: /dev/null
test!(container_shall_only_have_configured_fds, {
    let runtime = Northstar::launch_install_test_container().await?;
    runtime.test_cmds("inspect").await;
    runtime.start(TEST_CONTAINER).await?;
    assume("/proc/self/fd/0: /dev/null", 5).await?;
    assume("/proc/self/fd/1: pipe:.*", 5).await?;
    assume("/proc/self/fd/2: /dev/null", 5).await?;
    assume("total: 3", 5).await?;

    runtime.shutdown().await
});

// Check if /proc is mounted ro
test!(proc_is_mounted_ro, {
    let runtime = Northstar::launch_install_test_container().await?;
    runtime.test_cmds("inspect").await;
    runtime.start(TEST_CONTAINER).await?;
    assume("proc /proc proc ro,", 5).await?;
    runtime.shutdown().await
});

// Open many connections to the runtime
test!(open_many_connections_to_the_runtime_and_shutdown, {
    let runtime = Northstar::launch().await?;

    let console = runtime.config().console.as_ref().unwrap();

    let mut clients = Vec::new();
    for _ in 0..100 {
        let client =
            api::client::Client::new(&console, None, time::Duration::from_secs(30)).await?;
        clients.push(client);
    }

    let result = runtime.shutdown().await;

    for client in &clients {
        assert!(client.containers().await.is_err());
    }
    clients.clear();

    result
});

test!(check_api_version_on_connect, {
    let runtime = Northstar::launch().await?;

    trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

    let console = runtime.config().console.as_ref().unwrap();
    let mut connection = api::codec::framed(UnixStream::connect(console.path()).await?);

    // Send a connect with an version unequal to the one defined in the model
    let mut version = api::model::version();
    version.patch += 1;

    let connect = api::model::Connect::Connect {
        version,
        subscribe_notifications: false,
    };
    let connect_message = api::model::Message::new_connect(connect);
    connection.send(connect_message.clone()).await?;

    // Receive connect nack
    let connack = connection.next().await.unwrap().unwrap();

    drop(connection);

    let mut expected_message = model::Message::new_connect(model::Connect::ConnectNack(
        ConnectNack::InvalidProtocolVersion(model::version()),
    ));

    // The reply shall contain the same uuid as the request
    expected_message.id = connect_message.id.clone();

    assert_eq!(connack, expected_message);

    runtime.shutdown().await
});

test!(cgroups_memory, {
    let runtime = Northstar::launch_install_test_container().await?;

    for _ in 0..10 {
        runtime.test_cmds("leak-memory").await;
        runtime.start(TEST_CONTAINER).await?;
        assume("Process test_container:0.0.1 is out of memory", 10).await?;
        assume(
            "Stopped test_container:0.0.1 with status Signaled\\(SIGTERM\\)",
            10,
        )
        .await?;
    }

    runtime.shutdown().await
});
