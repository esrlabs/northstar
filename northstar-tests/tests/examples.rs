use anyhow::Result;
use northstar::api::model::{ExitStatus, Notification};
use northstar_tests::{containers::*, logger::assume, runtime::client, runtime_test};

// Start crashing example
#[runtime_test]
fn crashing() -> Result<()> {
    client().install(EXAMPLE_CRASHING_NPK, "mem").await?;
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
        .await
}

// Start console example
#[runtime_test]
fn console() -> Result<()> {
    client().install(EXAMPLE_CONSOLE_NPK, "mem").await?;
    client().start(EXAMPLE_CONSOLE).await?;
    // The console example stop itself - so wait for it...
    assume("Container console:0.0.1 connected with permissions .*", 5).await?;
    assume("Killing console:0.0.1 with SIGTERM", 5).await
}

// Start cpueater example and assume log message
#[runtime_test]
fn cpueater() -> Result<()> {
    client().install(EXAMPLE_CPUEATER_NPK, "mem").await?;
    client().start(EXAMPLE_CPUEATER).await?;
    assume("Eating CPU", 5).await?;

    client().stop(EXAMPLE_CPUEATER, 10).await
}

// Start hello-ferris example
#[runtime_test]
fn hello_ferris() -> Result<()> {
    client().install(EXAMPLE_FERRIS_NPK, "mem").await?;
    client().install(EXAMPLE_MESSAGE_0_0_1_NPK, "mem").await?;
    client().install(EXAMPLE_HELLO_FERRIS_NPK, "mem").await?;
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
        .await
}

// Start hello-resource example
#[runtime_test]
fn hello_resource() -> Result<()> {
    client().install(EXAMPLE_MESSAGE_0_0_2_NPK, "mem").await?;
    client().install(EXAMPLE_HELLO_RESOURCE_NPK, "mem").await?;
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
    .await
}

// Start inspect example
#[runtime_test]
fn inspect() -> Result<()> {
    client().install(EXAMPLE_INSPECT_NPK, "mem").await?;
    client().start(EXAMPLE_INSPECT).await?;
    client().stop(EXAMPLE_INSPECT, 5).await
}

// // Start memeater example
// #[runtime_test]
// async fn memeater() -> Result<()> {
//     client().install(&EXAMPLE_MEMEATER_NPK, "mem").await?;
//     client().start(EXAMPLE_MEMEATER).await?;
//     assume("Process memeater:0.0.1 is out of memory", 20).await
// }

// Start persistence example and check output
#[runtime_test]
fn persistence() -> Result<()> {
    client().install(EXAMPLE_PERSISTENCE_NPK, "mem").await?;
    client().start(EXAMPLE_PERSISTENCE).await?;
    assume("Writing Hello! to /data/file", 5).await?;
    assume("Content of /data/file: Hello!", 5).await
}

// Start seccomp example
#[runtime_test]
fn seccomp() -> Result<()> {
    client().install(EXAMPLE_SECCOMP_NPK, "mem").await?;
    client().start(EXAMPLE_SECCOMP).await?;
    Ok(())
}

// Redis
#[runtime_test]
fn redis() -> Result<()> {
    client().install(EXAMPLE_REDIS_NPK, "mem").await?;
    client().install(EXAMPLE_REDIS_CLIENT_NPK, "mem").await?;
    client().start(EXAMPLE_REDIS).await?;
    client().start(EXAMPLE_REDIS_CLIENT).await?;
    assume("Starting...", 5).await?;
    assume("Received: b\"#StandWithUkraine\"", 5).await?;
    Ok(())
}
