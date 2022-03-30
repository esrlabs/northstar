use std::path::{Path, PathBuf};

use futures::{SinkExt, StreamExt};
use log::debug;
use logger::assume;
use northstar::api::{
    self,
    model::{self, ConnectNack, ExitStatus, Notification},
};
use northstar_tests::{containers::*, logger, runtime::client, test};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UnixStream,
};

// Test a good and bad log assumption
test!(logger_smoketest, {
    debug!("Yippie");
    assume("Yippie", 3).await?;
    assert!(assume("Juhuuu!", 1).await.is_err());
});

// Install and uninstall is a loop. After a number of installation
// try to start the test container
test!(install_uninstall_test_container, {
    for _ in 0u32..10 {
        client().install_test_container().await?;
        client().uninstall_test_container().await?;
    }
});

// Install a container that already exists with the same name and version
test!(install_duplicate, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    assert!(client().install_test_container().await.is_err());
});

// Install a container that already exists in another repository
test!(install_duplicate_other_repository, {
    client().install(TEST_CONTAINER_NPK, "mem").await?;
    assert!(client().install(TEST_CONTAINER_NPK, "fs").await.is_err());
});

// Install a container to the file system backed repository
test!(install_uninstall_to_fs_repository, {
    client().install_test_resource().await?;
    for _ in 0u32..5 {
        client().install(TEST_CONTAINER_NPK, "fs").await?;
        client().start_with_args(TEST_CONTAINER, ["sleep"]).await?;
        assume("Sleeping", 5u64).await?;
        client().stop(TEST_CONTAINER, 5).await?;
        assume("Process test-container:0.0.1 exited", 5).await?;
        client().uninstall_test_container().await?;
    }
});

// Start and stop a container multiple times
test!(start_stop, {
    client().install_test_container().await?;
    client().install_test_resource().await?;

    for _ in 0..10u32 {
        client().start_with_args(TEST_CONTAINER, ["sleep"]).await?;
        assume("Sleeping", 5u64).await?;
        client().stop(TEST_CONTAINER, 5).await?;
        assume("Process test-container:0.0.1 exited", 5).await?;
    }
});

// Install and uninsteall the example npks
test!(install_uninstall_examples, {
    client().install(EXAMPLE_CPUEATER_NPK, "mem").await?;
    client().install(EXAMPLE_CONSOLE_NPK, "mem").await?;
    client().install(EXAMPLE_CRASHING_NPK, "mem").await?;
    client().install(EXAMPLE_FERRIS_NPK, "mem").await?;
    client().install(EXAMPLE_HELLO_FERRIS_NPK, "mem").await?;
    client().install(EXAMPLE_HELLO_RESOURCE_NPK, "mem").await?;
    client().install(EXAMPLE_INSPECT_NPK, "mem").await?;
    client().install(EXAMPLE_MEMEATER_NPK, "mem").await?;
    client().install(EXAMPLE_MESSAGE_0_0_1_NPK, "mem").await?;
    client().install(EXAMPLE_MESSAGE_0_0_2_NPK, "mem").await?;
    client().install(EXAMPLE_PERSISTENCE_NPK, "mem").await?;
    client().install(EXAMPLE_SECCOMP_NPK, "mem").await?;
    client().install(TEST_CONTAINER_NPK, "mem").await?;
    client().install(TEST_RESOURCE_NPK, "mem").await?;

    client().uninstall(EXAMPLE_CPUEATER).await?;
    client().uninstall(EXAMPLE_CONSOLE).await?;
    client().uninstall(EXAMPLE_CRASHING).await?;
    client().uninstall(EXAMPLE_FERRIS).await?;
    client().uninstall(EXAMPLE_HELLO_FERRIS).await?;
    client().uninstall(EXAMPLE_HELLO_RESOURCE).await?;
    client().uninstall(EXAMPLE_INSPECT).await?;
    client().uninstall(EXAMPLE_MEMEATER).await?;
    client().uninstall(EXAMPLE_MESSAGE_0_0_1).await?;
    client().uninstall(EXAMPLE_MESSAGE_0_0_2).await?;
    client().uninstall(EXAMPLE_PERSISTENCE).await?;
    client().uninstall(EXAMPLE_SECCOMP).await?;
    client().uninstall(TEST_CONTAINER).await?;
    client().uninstall(TEST_RESOURCE).await?;
});

// Mount and umount all containers known to the client()
test!(mount_umount, {
    client().install(EXAMPLE_CPUEATER_NPK, "mem").await?;
    client().install(EXAMPLE_CONSOLE_NPK, "mem").await?;
    client().install(EXAMPLE_CRASHING_NPK, "mem").await?;
    client().install(EXAMPLE_FERRIS_NPK, "mem").await?;
    client().install(EXAMPLE_HELLO_FERRIS_NPK, "mem").await?;
    client().install(EXAMPLE_HELLO_RESOURCE_NPK, "mem").await?;
    client().install(EXAMPLE_INSPECT_NPK, "mem").await?;
    client().install(EXAMPLE_MEMEATER_NPK, "mem").await?;
    client().install(EXAMPLE_MESSAGE_0_0_1_NPK, "mem").await?;
    client().install(EXAMPLE_MESSAGE_0_0_2_NPK, "mem").await?;
    client().install(EXAMPLE_PERSISTENCE_NPK, "mem").await?;
    client().install(EXAMPLE_SECCOMP_NPK, "mem").await?;
    client().install(TEST_CONTAINER_NPK, "mem").await?;
    client().install(TEST_RESOURCE_NPK, "mem").await?;

    let mut containers = client().containers().await?;
    client()
        .mount(containers.drain(..).map(|c| c.container))
        .await?;

    let containers = &mut client().containers().await?;
    for c in containers.iter().filter(|c| c.mounted) {
        client().umount(c.container.clone()).await?;
    }
});

// Try to stop a not started container and expect an Err
test!(try_to_stop_unknown_container, {
    let container = "foo:0.0.1:default";
    assert!(client().stop(container, 5).await.is_err());
});

// Try to start a container which is not installed/known
test!(try_to_start_unknown_container, {
    let container = "unknown_application:0.0.12:asdf";
    assert!(client().start(container).await.is_err());
});

// Try to start a container where a dependency is missing
test!(try_to_start_containter_that_misses_a_resource, {
    client().install_test_container().await?;
    // The TEST_RESOURCE is not installed.
    assert!(client().start(TEST_CONTAINER).await.is_err());
});

// Start a container that uses a resource
test!(check_test_container_resource_usage, {
    client().install_test_container().await?;
    client().install_test_resource().await?;

    // Start the test_container process
    client()
        .start_with_args(TEST_CONTAINER, ["cat", "/resource/hello"])
        .await?;

    assume("hello from test resource", 5).await?;

    // The container might have finished at this point
    client().stop(TEST_CONTAINER, 5).await?;

    client().uninstall_test_container().await?;
    client().uninstall_test_resource().await?;
});

// Try to uninstall a started container
test!(try_to_uninstall_a_started_container, {
    client().install_test_container().await?;
    client().install_test_resource().await?;

    client().start_with_args(TEST_CONTAINER, ["sleep"]).await?;
    assume("Sleeping...", 5u64).await?;

    let result = client().uninstall_test_container().await;
    assert!(result.is_err());

    client().stop(TEST_CONTAINER, 5).await?;
});

test!(start_mounted_container_with_not_mounted_resource, {
    client().install_test_container().await?;
    client().install_test_resource().await?;

    // Start a container that depends on a resource.
    client().start_with_args(TEST_CONTAINER, ["sleep"]).await?;
    assume("Sleeping...", 5u64).await?;
    client().stop(TEST_CONTAINER, 5).await?;

    // Umount the resource and start the container again.
    client().umount(TEST_RESOURCE).await?;

    client().start_with_args(TEST_CONTAINER, ["sleep"]).await?;
    assume("Sleeping...", 5u64).await?;

    client().stop(TEST_CONTAINER, 5).await?;
});

// The test is flaky and needs to listen for notifications
// in order to be implemented correctly
test!(container_crash_exit, {
    client().install_test_container().await?;
    client().install_test_resource().await?;

    for _ in 0..10 {
        client().start_with_args(TEST_CONTAINER, ["crash"]).await?;
        client()
            .assume_notification(
                |n| {
                    matches!(
                        n,
                        Notification::Exit {
                            status: ExitStatus::Signalled { signal: 6 },
                            ..
                        }
                    )
                },
                15,
            )
            .await?;
    }

    client().uninstall_test_container().await?;
    client().uninstall_test_resource().await?;
});

// Check uid. In the manifest of the test container the uid
// is set to 1000
test!(container_uses_correct_uid, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    client()
        .start_with_args(TEST_CONTAINER, ["inspect"])
        .await?;
    assume("getuid: 1000", 5).await?;
    client().stop(TEST_CONTAINER, 5).await?;
});

// Check gid. In the manifest of the test container the gid
// is set to 1000
test!(container_uses_correct_gid, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    client()
        .start_with_args(TEST_CONTAINER, ["inspect"])
        .await?;
    assume("getgid: 1000", 5).await?;
    client().stop(TEST_CONTAINER, 5).await?;
});

// Check parent pid. Northstar starts an init process which must have pid 1.
test!(container_ppid_must_be_init, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    client()
        .start_with_args(TEST_CONTAINER, ["inspect"])
        .await?;
    assume("getppid: 1", 5).await?;
    client().stop(TEST_CONTAINER, 5).await?;
});

// Check session id which needs to be pid of init
test!(container_sid_must_be_init_or_none, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    client()
        .start_with_args(TEST_CONTAINER, ["inspect"])
        .await?;
    assume("getsid: 1", 5).await?;
    client().stop(TEST_CONTAINER, 5).await?;
});

// The test container only gets the cap_kill capability. See the manifest
test!(container_shall_only_have_configured_capabilities, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    client()
        .start_with_args(TEST_CONTAINER, ["inspect"])
        .await?;
    assume("caps bounding: \\{\\}", 10).await?;
    assume("caps effective: \\{\\}", 10).await?;
    assume("caps permitted: \\{\\}", 10).await?;
    client().stop(TEST_CONTAINER, 5).await?;
});

// The test container has a configured resource limit of tasks
test!(container_rlimits, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    client()
        .start_with_args(TEST_CONTAINER, ["inspect"])
        .await?;
    assume(
        "Max processes             10000                20000                processes",
        10,
    )
    .await?;
    client().stop(TEST_CONTAINER, 5).await?;
});

// Check whether after a client() start, container start and shutdown
// any file descriptor is leaked
test!(start_stop_and_container_shall_not_leak_file_descriptors, {
    /// Collect a set of files in /proc/$$/fd
    fn fds() -> Result<Vec<PathBuf>, std::io::Error> {
        let mut links = std::fs::read_dir("/proc/self/fd")?
            .filter_map(Result::ok)
            .flat_map(|entry| entry.path().read_link())
            .collect::<Vec<_>>();
        links.sort();
        Ok(links)
    }

    let before = fds()?;

    client().install_test_container().await?;
    client().install_test_resource().await?;

    client().start_with_args(TEST_CONTAINER, ["sleep"]).await?;
    assume("Sleeping", 5).await?;
    client().stop(TEST_CONTAINER, 5).await?;

    client().uninstall_test_container().await?;
    client().uninstall_test_resource().await?;

    // Compare the list of fds before and after the RT run.
    assert_eq!(before, fds()?);

    let result = client().shutdown().await;

    assert!(result.is_ok());
});

// Check open file descriptors in the test container that should be
// stdin: /dev/null
// stdout: some pipe
// stderr: /dev/null
test!(container_shall_only_have_configured_fds, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    client()
        .start_with_args(TEST_CONTAINER, ["inspect"])
        .await?;
    assume("/proc/self/fd/0: /dev/null", 5).await?;
    assume("/proc/self/fd/1: socket", 5).await?;
    assume("/proc/self/fd/2: socket", 5).await?;
    assume("total: 3", 5).await?;
    client().stop(TEST_CONTAINER, 5).await?;
});

// Check if /proc is mounted ro
test!(proc_is_mounted_ro, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    client()
        .start_with_args(TEST_CONTAINER, ["inspect"])
        .await?;
    assume("proc /proc proc ro,", 5).await?;
    client().stop(TEST_CONTAINER, 5).await?;
});

// Check that mount flags nosuid,nodev,noexec are properly set for bind mounts
// assumption: mount flags are always listed the same order (according mount.h)
// note: MS_REC is not explicitly listed an cannot be checked with this test
test!(mount_flags_are_set_for_bind_mounts, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    client()
        .start_with_args(TEST_CONTAINER, ["inspect"])
        .await?;
    assume(
        "/.* /resource \\w+ ro,(\\w+,)*nosuid,(\\w+,)*nodev,(\\w+,)*noexec",
        5,
    )
    .await?;
    client().stop(TEST_CONTAINER, 5).await?;
});

// The test container only gets the cap_kill capability. See the manifest
test!(selinux_mounted_squasfs_has_correct_context, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    client()
        .start_with_args(TEST_CONTAINER, ["inspect"])
        .await?;
    // Only expect selinux context if system supports it
    if Path::new("/sys/fs/selinux/enforce").exists() {
        assume(
            "/.* squashfs (\\w+,)*context=unconfined_u:object_r:user_home_t:s0",
            5,
        )
        .await?;
    } else {
        assume("/.* squashfs (\\w+,)*", 5).await?;
    }
    client().stop(TEST_CONTAINER, 5).await?;
});

// Call syscall with specifically allowed argument
test!(seccomp_allowed_syscall_with_allowed_arg, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    client()
        .start_with_args(TEST_CONTAINER, ["call-delete-module", "1"])
        .await?;
    assume("delete_module syscall was successful", 5).await?;
    client().stop(TEST_CONTAINER, 5).await?;
});

// Call syscall with argument allowed by bitmask
test!(seccomp_allowed_syscall_with_masked_arg, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    client()
        .start_with_args(TEST_CONTAINER, ["call-delete-module", "4"])
        .await?;
    assume("delete_module syscall was successful", 5).await?;
    client().stop(TEST_CONTAINER, 5).await?;
});

// Call syscall with prohibited argument
test!(seccomp_allowed_syscall_with_prohibited_arg, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    client()
        .start_with_args(TEST_CONTAINER, ["call-delete-module", "7"])
        .await?;

    let n = |n: &Notification| {
        matches!(n,
        Notification::Exit {
            status: ExitStatus::Signalled { signal },
            ..
        } if signal == &31)
    };
    client().assume_notification(n, 5).await?;
});

// Iterate all exit codes in the u8 range
test!(exitcodes, {
    client().install_test_container().await?;
    client().install_test_resource().await?;
    for c in &[0, 1, 10, 127, 128, 255] {
        client()
            .start_with_args(TEST_CONTAINER, ["exit".to_string(), c.to_string()])
            .await?;
        let n = |n: &Notification| {
            matches!(n, Notification::Exit {
                status: ExitStatus::Exit { code },
                ..
            } if code == c)
        };
        client().assume_notification(n, 5).await?;
    }
});

// Verify that the client() reject a version mismatch in Connect
test!(check_api_version_on_connect, {
    trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

    let mut connection = api::codec::Framed::new(
        UnixStream::connect(&northstar_tests::runtime::console().path()).await?,
    );

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

    let error = ConnectNack::InvalidProtocolVersion {
        version: model::version(),
    };
    let expected_message = model::Message::new_connect(model::Connect::Nack { error });

    assert_eq!(connack, expected_message);
});

// Check printing on stdout and stderr
test!(stdout_stderr, {
    client().install_test_container().await?;
    client().install_test_resource().await?;

    let args = ["print", "--io", "stdout", "hello stdout"];
    client().start_with_args(TEST_CONTAINER, args).await?;
    assume("hello stdout", 10).await?;
    client().stop(TEST_CONTAINER, 5).await?;

    let args = ["print", "--io", "stderr", "hello stderr"];
    client().start_with_args(TEST_CONTAINER, args).await?;
    assume("hello stderr", 10).await?;
    client().stop(TEST_CONTAINER, 5).await?;
});
