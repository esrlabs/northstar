use logger::assume;
use northstar::api::model::{ExitStatus, Notification};
use northstar_tests::{containers::*, logger, runtime::client, test};

// Start crashing example
test!(crashing, {
    client().install(EXAMPLE_CRASHING_NPK, "test-0").await?;
    client().start(EXAMPLE_CRASHING).await?;
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
            20,
        )
        .await?;
});

// Start console example
test!(console, {
    client().install(EXAMPLE_CONSOLE_NPK, "test-0").await?;
    client().start(EXAMPLE_CONSOLE).await?;
    // The console example stop itself - so wait for it...
    assume("Client console:0.0.1 connected", 5).await?;
    assume("Killing console:0.0.1 with SIGTERM", 5).await?;
});

// Start cpueater example and assume log message
test!(cpueater, {
    client().install(EXAMPLE_CPUEATER_NPK, "test-0").await?;
    client().start(EXAMPLE_CPUEATER).await?;
    assume("Eating CPU", 5).await?;

    client().stop(EXAMPLE_CPUEATER, 10).await?;
});

// Start hello-ferris example
test!(hello_ferris, {
    client().install(EXAMPLE_FERRIS_NPK, "test-0").await?;
    client()
        .install(EXAMPLE_MESSAGE_0_0_1_NPK, "test-0")
        .await?;
    client().install(EXAMPLE_HELLO_FERRIS_NPK, "test-0").await?;
    client().start(EXAMPLE_HELLO_FERRIS).await?;
    assume("Hello once more from 0.0.1!", 5).await?;
    // The hello-ferris example terminates after printing something.
    // Wait for the notification that it stopped, otherwise the client()
    // will try to shutdown the application which is already exited.
    client()
        .assume_notification(
            |n| {
                matches!(
                    n,
                    Notification::Exit {
                        status: ExitStatus::Exit { code: 0 },
                        ..
                    }
                )
            },
            15,
        )
        .await?;
});

// Start hello-resource example
test!(hello_resource, {
    client()
        .install(EXAMPLE_MESSAGE_0_0_2_NPK, "test-0")
        .await?;
    client()
        .install(EXAMPLE_HELLO_RESOURCE_NPK, "test-0")
        .await?;
    client().start(EXAMPLE_HELLO_RESOURCE).await?;
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
});

// Start inspect example
test!(inspect, {
    client().install(EXAMPLE_INSPECT_NPK, "test-0").await?;
    client().start(EXAMPLE_INSPECT).await?;
    client().stop(EXAMPLE_INSPECT, 5).await?;
});

// Start memeater example
// test!(memeater, {
//     let mut client() = Northstar::launch().await?;
//     client().install(&EXAMPLE_MEMEATER_NPK, "test-0").await?;
//     client().start(EXAMPLE_MEMEATER).await?;
//     assume("Process memeater:0.0.1 is out of memory", 20).await
// });

// Start persistence example and check output
test!(persistence, {
    client().install(EXAMPLE_PERSISTENCE_NPK, "test-0").await?;
    client().start(EXAMPLE_PERSISTENCE).await?;
    assume("Writing Hello! to /data/file", 5).await?;
    assume("Content of /data/file: Hello!", 5).await?;
});

// Start seccomp example
test!(seccomp, {
    client().install(EXAMPLE_SECCOMP_NPK, "test-0").await?;
    client().start(EXAMPLE_SECCOMP).await?;
});
