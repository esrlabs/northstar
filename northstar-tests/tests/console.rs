use std::{iter, path::Path};

use anyhow::{Context, Result};
use api::model::Error as ModelError;
use futures::SinkExt;
use northstar_client::error::RequestError;
use northstar_runtime::api::{
    self,
    model::{self, ConnectNack, Container},
};
use northstar_tests::runtime_test;
use tokio::{net::UnixStream, time::Duration};

/// Connect a client to the runtime console without any permission configured.
async fn connect_none() -> Result<northstar_client::Client<UnixStream>> {
    let io = UnixStream::connect(&northstar_tests::runtime::console_none().path()).await?;
    northstar_client::Client::new(io, None, Duration::from_secs(10))
        .await
        .context("failed to connect to the runtime")
}

// Verify that the client() reject a version mismatch in Connect
#[runtime_test]
async fn api_version() -> Result<()> {
    let mut connection = api::codec::Framed::new(
        UnixStream::connect(&northstar_tests::runtime::console_none().path()).await?,
    );

    // Send a connect with an version unequal to the one defined in the model
    let mut version = api::VERSION;
    version.major += 1;

    let connect = api::model::Connect::Connect {
        version,
        subscribe_notifications: false,
    };
    let connect_message = api::model::Message::Connect { connect };
    connection.send(connect_message.clone()).await?;

    // Receive connect nack
    let connack = connection.next().await.unwrap().unwrap();

    drop(connection);

    let error = ConnectNack::InvalidProtocolVersion {
        version: api::VERSION,
    };
    let connect = model::Connect::Nack { error };
    let expected_message = model::Message::Connect { connect };

    assert_eq!(connack, expected_message);
    Ok(())
}

/// Expect the connection to be closed if a request with a too long line is sent.
#[runtime_test]
async fn too_long_line() -> Result<()> {
    let timeout = Duration::from_secs(10);
    let io = UnixStream::connect(&northstar_tests::runtime::console_full().path()).await?;
    let mut client = northstar_client::Client::new(io, None, timeout).await?;

    // The default json line limit is 512K
    let container = Container::try_from("hello-world:0.0.1").unwrap();
    let mount = iter::repeat(container).take(100000).collect();

    match client.request(model::Request::Mount(mount)).await {
        Ok(_) => panic!("expected IO error"),
        Err(_) => Ok(()),
    }
}

/// Invalid install request
#[runtime_test]
async fn npk_size_limit_violation() -> Result<()> {
    let timeout = Duration::from_secs(10);
    let io = UnixStream::connect(&northstar_tests::runtime::console_full().path()).await?;
    let mut client = northstar_client::Client::new(io, None, timeout).await?;

    match client
        .request(model::Request::Install("mem".into(), 999999999))
        .await
    {
        Ok(_) => panic!("expected IO error"),
        Err(_) => Ok(()),
    }
}

// This tests blocks the test execution for min 5s which is not ideal
// when running the tests in a loop.
// /// Stale install request that shall timeout after some seconds
// #[runtime_test]
// async fn stale_install() -> Result<()> {
//     let timeout = Duration::from_secs(10);
//     let io = UnixStream::connect(&northstar_tests::runtime::console_full().path()).await?;
//     let mut client = api::client::Client::new(io, None, timeout).await?;

//     let response = client
//         .request(model::Request::Install("mem".into(), 100))
//         .await;
//     assert!(response.is_err());

//     Ok(())
// }

/// Check that subscribing to notifications is not permitted on the `console_none` url.
#[runtime_test]
async fn notifications() -> Result<()> {
    let io = UnixStream::connect(&northstar_tests::runtime::console_none().path()).await?;
    assert!(
        northstar_client::Client::new(io, Some(10), Duration::from_secs(10))
            .await
            .is_err()
    );
    Ok(())
}

#[runtime_test]
async fn permissions_list() -> Result<()> {
    assert!(matches!(
        connect_none().await?.list().await,
        Err(RequestError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_repositories() -> Result<()> {
    assert!(matches!(
        connect_none().await?.repositories().await,
        Err(RequestError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_start() -> Result<()> {
    assert!(matches!(
        connect_none().await?.start("hello-world:0.0.1").await,
        Err(RequestError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    assert!(matches!(
        connect_none()
            .await?
            .start_with_args("hello-world:0.0.1", ["--help"])
            .await,
        Err(RequestError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    assert!(matches!(
        connect_none()
            .await?
            .start_with_args_env("hello-world:0.0.1", ["--help"], [("HELLO", "YOU")])
            .await,
        Err(RequestError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_kill() -> Result<()> {
    assert!(matches!(
        connect_none().await?.kill("hello-world:0.0.1", 15).await,
        Err(RequestError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_install() -> Result<()> {
    assert!(matches!(
        connect_none()
            .await?
            .install_file(Path::new("/etc/hosts"), "mem")
            .await,
        Err(RequestError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_uninstall() -> Result<()> {
    assert!(matches!(
        connect_none().await?.uninstall("hello-world:0.0.1").await,
        Err(RequestError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Result::<()>::Ok(())
}

#[runtime_test]
async fn permissions_mount() -> Result<()> {
    assert!(matches!(
        connect_none().await?.mount("hello-world:0.0.1").await,
        Err(RequestError::Runtime(ModelError::PermissionDenied { .. }))
    ));

    assert!(matches!(
        connect_none()
            .await?
            .mount_all(["hello-world:0.0.1", "crashing:0.0.1"])
            .await,
        Err(RequestError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_umount() -> Result<()> {
    assert!(matches!(
        connect_none().await?.umount("hello-world:0.0.1").await,
        Err(RequestError::Runtime(ModelError::PermissionDenied { .. }))
    ));

    assert!(matches!(
        connect_none()
            .await?
            .umount_all(["hello-world:0.0.1", "crashing:0.0.1"])
            .await,
        Err(RequestError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_inspect() -> Result<()> {
    assert!(matches!(
        connect_none().await?.inspect("hello_world:0.0.1").await,
        Err(RequestError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}
