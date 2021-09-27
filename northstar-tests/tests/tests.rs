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
use northstar_tests::{containers::*, logger, runtime::Northstar, test};
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

// Install and uninstall is a loop. After a number of installation
// try to start the test container
test!(install_uninstall_test_container, {
    let mut runtime = Northstar::launch().await?;
    for _ in 0u32..10 {
        runtime.install_test_container().await?;
        runtime.uninstall_test_container().await?;
    }
    runtime.shutdown().await
});

// Install a container that already exists with the same name and version
test!(install_duplicate, {
    let mut runtime = Northstar::launch().await?;
    runtime.install_test_container().await?;
    assert!(runtime.install_test_container().await.is_err());
    runtime.shutdown().await
});

// Start and stop a container multiple times
test!(start_stop_test_container_with_waiting, {
    let mut runtime = Northstar::launch_install_test_container().await?;

    for _ in 0..10u32 {
        runtime.start_with_args(TEST_CONTAINER, ["sleep"]).await?;
        assume("Sleeping", 5u64).await?;
        runtime.stop(TEST_CONTAINER, 5).await?;
        assume("Process test-container:0.0.1 exited", 5).await?;
    }

    runtime.shutdown().await
});

// Mount and umount all containers known to the runtime
test!(mount_umount_test_container_via_client, {
    let mut runtime = Northstar::launch_install_test_container().await?;

    // Mount
    let mut containers = runtime.containers().await?;
    runtime
        .mount(containers.drain(..).map(|c| c.container))
        .await?;

    // Umount
    let containers = &mut runtime.containers().await?;
    for c in containers.iter().filter(|c| c.mounted) {
        runtime.umount(c.container.clone()).await?;
    }

    runtime.shutdown().await
});

// Try to stop a not started container and expect an Err
test!(try_to_stop_unknown_container, {
    let mut runtime = Northstar::launch().await?;
    let container = "foo:0.0.1:default";
    assert!(runtime.stop(container, 5).await.is_err());
    runtime.shutdown().await
});

// Try to start a container which is not installed/known
test!(try_to_start_unknown_container, {
    let mut runtime = Northstar::launch().await?;
    let container = "unknown_application:0.0.12:asdf";
    assert!(runtime.start(container).await.is_err());
    runtime.shutdown().await
});

// Try to start a container where a dependency is missing
test!(try_to_start_containter_that_misses_a_resource, {
    let mut runtime = Northstar::launch().await?;
    runtime.install_test_container().await?;
    // The TEST_RESOURCE is not installed.
    assert!(runtime.start(TEST_CONTAINER).await.is_err());
    runtime.shutdown().await
});

// Start a container that uses a resource
test!(check_test_container_resource_usage, {
    let mut runtime = Northstar::launch_install_test_container().await?;

    // Start the test_container process
    runtime
        .start_with_args(TEST_CONTAINER, ["cat", "/resource/hello"])
        .await?;

    assume("hello from test resource", 5).await?;

    // The container might have finished at this point
    runtime.stop(TEST_CONTAINER, 5).await?;

    runtime.uninstall_test_container().await?;
    runtime.uninstall_test_resource().await?;

    runtime.shutdown().await
});

// Try to uninstall a started container
test!(try_to_uninstall_a_started_container, {
    let mut runtime = Northstar::launch_install_test_container().await?;

    runtime.start_with_args(TEST_CONTAINER, ["sleep"]).await?;
    assume("test-container: Sleeping...", 5u64).await?;

    let result = runtime.uninstall_test_container().await;
    assert!(result.is_err());

    runtime.stop(TEST_CONTAINER, 5).await?;

    runtime.shutdown().await
});

test!(start_mounted_container_with_not_mounted_resource, {
    let mut runtime = Northstar::launch_install_test_container().await?;

    // Start a container that depends on a resource.
    runtime.start_with_args(TEST_CONTAINER, ["sleep"]).await?;
    assume("test-container: Sleeping...", 5u64).await?;
    runtime.stop(TEST_CONTAINER, 5).await?;

    // Umount the resource and start the container again.
    runtime.umount(TEST_RESOURCE).await?;

    runtime.start_with_args(TEST_CONTAINER, ["sleep"]).await?;
    assume("test-container: Sleeping...", 5u64).await?;

    runtime.stop(TEST_CONTAINER, 5).await?;

    runtime.shutdown().await
});

// The test is flaky and needs to listen for notifications
// in order to be implemented correctly
test!(container_crash_exit, {
    let mut runtime = Northstar::launch_install_test_container().await?;

    for _ in 0..10 {
        runtime.start_with_args(TEST_CONTAINER, ["crash"]).await?;
        runtime
            .assume_notification(
                |n| matches!(n, Notification::Exit(_, ExitStatus::Signaled(6))),
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
    let mut runtime = Northstar::launch_install_test_container().await?;
    runtime.start_with_args(TEST_CONTAINER, ["inspect"]).await?;
    assume("getuid: 1000", 5).await?;
    runtime.stop(TEST_CONTAINER, 5).await?;
    runtime.shutdown().await
});

// Check gid. In the manifest of the test container the gid
// is set to 1000
test!(container_uses_correct_gid, {
    let mut runtime = Northstar::launch_install_test_container().await?;
    runtime.start_with_args(TEST_CONTAINER, ["inspect"]).await?;
    assume("getgid: 1000", 5).await?;
    runtime.stop(TEST_CONTAINER, 5).await?;
    runtime.shutdown().await
});

// Check parent pid. Northstar starts an init process which must have pid 1.
test!(container_ppid_must_be_init, {
    let mut runtime = Northstar::launch_install_test_container().await?;
    runtime.start_with_args(TEST_CONTAINER, ["inspect"]).await?;
    assume("getppid: 1", 5).await?;
    runtime.stop(TEST_CONTAINER, 5).await?;
    runtime.shutdown().await
});

// Check session id which needs to be pid of init
test!(container_sid_must_be_init_or_none, {
    let mut runtime = Northstar::launch_install_test_container().await?;
    runtime.start_with_args(TEST_CONTAINER, ["inspect"]).await?;
    assume("getsid: 1", 5).await?;
    runtime.stop(TEST_CONTAINER, 5).await?;
    runtime.shutdown().await
});

// The test container only gets the cap_kill capability. See the manifest
test!(container_shall_only_have_configured_capabilities, {
    let mut runtime = Northstar::launch_install_test_container().await?;
    runtime.start_with_args(TEST_CONTAINER, ["inspect"]).await?;
    assume("caps bounding: \\{\\}", 10).await?;
    assume("caps effective: \\{\\}", 10).await?;
    assume("caps permitted: \\{\\}", 10).await?;
    runtime.stop(TEST_CONTAINER, 5).await?;
    runtime.shutdown().await
});

// The test container has a configured resource limit of tasks
test!(container_rlimits, {
    let mut runtime = Northstar::launch_install_test_container().await?;
    runtime.start_with_args(TEST_CONTAINER, ["inspect"]).await?;
    assume(
        "Max processes             10000                20000                processes",
        10,
    )
    .await?;
    runtime.stop(TEST_CONTAINER, 5).await?;
    runtime.shutdown().await
});

// Check whether after a runtime start, container start and shutdown
// any file descriptor is leaked
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

        let mut runtime = Northstar::launch_install_test_container().await?;

        runtime.start_with_args(TEST_CONTAINER, ["sleep"]).await?;
        assume("test-container: Sleeping", 5).await?;
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
    let mut runtime = Northstar::launch_install_test_container().await?;
    runtime.start_with_args(TEST_CONTAINER, ["inspect"]).await?;
    assume("/proc/self/fd/0: /dev/null", 5).await?;
    assume("/proc/self/fd/1: pipe:.*", 5).await?;
    assume("/proc/self/fd/2: pipe:.*", 5).await?;
    assume("total: 3", 5).await?;
    runtime.stop(TEST_CONTAINER, 5).await?;

    runtime.shutdown().await
});

// Check if /proc is mounted ro
test!(proc_is_mounted_ro, {
    let mut runtime = Northstar::launch_install_test_container().await?;
    runtime.start_with_args(TEST_CONTAINER, ["inspect"]).await?;
    assume("proc /proc proc ro,", 5).await?;
    runtime.stop(TEST_CONTAINER, 5).await?;
    runtime.shutdown().await
});

// Call syscall with specifically allowed argument
test!(seccomp_allowed_syscall_with_allowed_arg, {
    let mut runtime = Northstar::launch_install_test_container().await?;
    runtime
        .start_with_args(TEST_CONTAINER, ["call-delete-module", "1"])
        .await?;
    assume("delete_module syscall was successful", 5).await?;
    runtime.stop(TEST_CONTAINER, 5).await?;
    runtime.shutdown().await
});

// Call syscall with argument allowed by bitmask
test!(seccomp_allowed_syscall_with_masked_arg, {
    let mut runtime = Northstar::launch_install_test_container().await?;
    runtime
        .start_with_args(TEST_CONTAINER, ["call-delete-module", "4"])
        .await?;
    assume("delete_module syscall was successful", 5).await?;
    runtime.stop(TEST_CONTAINER, 5).await?;
    runtime.shutdown().await
});

// Call syscall with prohibited argument
test!(seccomp_allowed_syscall_with_prohibited_arg, {
    let mut runtime = Northstar::launch_install_test_container().await?;
    runtime
        .start_with_args(TEST_CONTAINER, ["call-delete-module", "7"])
        .await?;
    assume(r"exited after .* with status Signaled\(SIGSYS\)", 5).await?;
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

    for client in &mut clients {
        assert!(client.containers().await.is_err());
    }
    clients.clear();

    result
});

// Verify that the runtime reject a version mismatch in Connect
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

    let expected_message = model::Message::new_connect(model::Connect::ConnectNack(
        ConnectNack::InvalidProtocolVersion(model::version()),
    ));

    assert_eq!(connack, expected_message);

    runtime.shutdown().await
});

mod example {
    use super::*;

    // Start crashing example
    test!(crashing, {
        let mut runtime = Northstar::launch().await?;
        runtime.install(&EXAMPLE_CRASHING_NPK).await?;
        runtime.start(EXAMPLE_CRASHING).await?;
        assume("Crashing in", 5).await?;
        runtime.shutdown().await
    });

    // Start cpueater example and assume log message
    test!(cpueater, {
        let mut runtime = Northstar::launch().await?;
        runtime.install(&EXAMPLE_CPUEATER_NPK).await?;
        runtime.start(EXAMPLE_CPUEATER).await?;
        assume("Eating CPU", 5).await?;

        runtime.stop(EXAMPLE_CPUEATER, 10).await?;
        runtime.shutdown().await
    });

    // Start hello-ferris example
    test!(hello_ferris, {
        let mut runtime = Northstar::launch().await?;
        runtime.install(&EXAMPLE_FERRIS_NPK).await?;
        runtime.install(&EXAMPLE_MESSAGE_0_0_1_NPK).await?;
        runtime.install(&EXAMPLE_HELLO_FERRIS_NPK).await?;
        runtime.start(EXAMPLE_HELLO_FERRIS).await?;
        assume("Hello once more from 0.0.1!", 5).await?;
        // The hello-ferris example terminates after printing something.
        // Wait for the notification that it stopped, otherwise the runtime
        // will try to shutdown the application which is already exited.
        runtime
            .assume_notification(
                |n| matches!(n, Notification::Exit(_, ExitStatus::Exit(0))),
                15,
            )
            .await?;

        runtime.shutdown().await
    });

    // Start hello-resource example
    test!(hello_resource, {
        let mut runtime = Northstar::launch().await?;
        runtime.install(&EXAMPLE_MESSAGE_0_0_2_NPK).await?;
        runtime.install(&EXAMPLE_HELLO_RESOURCE_NPK).await?;
        runtime.start(EXAMPLE_HELLO_RESOURCE).await?;
        assume(
            "0: Content of /message/hello: Hello once more from v0.0.2!",
            5,
        )
        .await?;
        assume(
            "1: Content of /message/hello: Hello once more from v0.0.2!",
            5,
        )
        .await?;
        runtime.shutdown().await
    });

    // Start inspect example
    test!(inspect, {
        let mut runtime = Northstar::launch().await?;
        runtime.install(&EXAMPLE_INSPECT_NPK).await?;
        runtime.start(EXAMPLE_INSPECT).await?;
        runtime.stop(EXAMPLE_INSPECT, 5).await?;
        // TODO
        runtime.shutdown().await
    });

    // Start memeater example
    test!(memeater, {
        let mut runtime = Northstar::launch().await?;
        runtime.install(&EXAMPLE_MEMEATER_NPK).await?;
        runtime.start(EXAMPLE_MEMEATER).await?;
        assume("Process memeater:0.0.1 is out of memory", 20).await?;
        runtime.shutdown().await
    });

    // Start persistence example and check output
    test!(persistence, {
        let mut runtime = Northstar::launch().await?;
        runtime.install(&EXAMPLE_PERSISTENCE_NPK).await?;
        runtime.start(EXAMPLE_PERSISTENCE).await?;
        assume("Writing Hello! to /data/file", 5).await?;
        assume("Content of /data/file: Hello!", 5).await?;
        runtime.shutdown().await
    });

    // Start seccomp example
    test!(seccomp, {
        let mut runtime = Northstar::launch().await?;
        runtime.install(&EXAMPLE_SECCOMP_NPK).await?;
        runtime.start(EXAMPLE_SECCOMP).await?;
        runtime.shutdown().await
    });
}
