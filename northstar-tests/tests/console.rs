use std::path::Path;

use anyhow::{Context, Result};
use api::{client::Error as ClientError, model::Error as ModelError};
use futures::{SinkExt, StreamExt};
use northstar::api::{
    self,
    model::{self, ConnectNack},
};
use northstar_tests::runtime_test;
use tokio::{net::UnixStream, time::Duration};

/// Connect a client to the runtime console without any permission configured.
async fn connect_none() -> Result<api::client::Client<UnixStream>> {
    let io = UnixStream::connect(&northstar_tests::runtime::console_none().path()).await?;
    api::client::Client::new(io, None, Duration::from_secs(10))
        .await
        .context("Failed to connect to the runtime")
}

// Verify that the client() reject a version mismatch in Connect
#[runtime_test]
async fn api_version() -> Result<()> {
    let mut connection = api::codec::Framed::new(
        UnixStream::connect(&northstar_tests::runtime::console_none().path()).await?,
    );

    // Send a connect with an version unequal to the one defined in the model
    let mut version = api::model::version();
    version.patch += 1;

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
        version: model::version(),
    };
    let connect = model::Connect::Nack { error };
    let expected_message = model::Message::Connect { connect };

    assert_eq!(connack, expected_message);
    Ok(())
}

/// Check that subscribing to notifications is not permitted on the `console_none` url.
#[runtime_test]
async fn notifications() -> Result<()> {
    let io = UnixStream::connect(&northstar_tests::runtime::console_none().path()).await?;
    assert!(
        api::client::Client::new(io, Some(10), Duration::from_secs(10))
            .await
            .is_err()
    );
    Ok(())
}

#[runtime_test]
async fn permissions_container() -> Result<()> {
    assert!(matches!(
        connect_none().await?.containers().await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_repositories() -> Result<()> {
    assert!(matches!(
        connect_none().await?.repositories().await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_start() -> Result<()> {
    assert!(matches!(
        connect_none().await?.start("hello-world:0.0.1").await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    assert!(matches!(
        connect_none()
            .await?
            .start_with_args("hello-world:0.0.1", ["--help"])
            .await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    assert!(matches!(
        connect_none()
            .await?
            .start_with_args_env("hello-world:0.0.1", ["--help"], [("HELLO", "YOU")])
            .await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_kill() -> Result<()> {
    assert!(matches!(
        connect_none().await?.kill("hello-world:0.0.1", 15).await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_install() -> Result<()> {
    assert!(matches!(
        connect_none()
            .await?
            .install(Path::new("/etc/hosts"), "mem")
            .await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_uninstall() -> Result<()> {
    assert!(matches!(
        connect_none().await?.uninstall("hello-world:0.0.1").await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Result::<()>::Ok(())
}

#[runtime_test]
async fn permissions_mount() -> Result<()> {
    assert!(matches!(
        connect_none().await?.mount("hello-world:0.0.1").await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));

    assert!(matches!(
        connect_none()
            .await?
            .mount_all(["hello-world:0.0.1", "crashing:0.0.1"])
            .await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_umount() -> Result<()> {
    assert!(matches!(
        connect_none().await?.umount("hello-world:0.0.1").await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));

    assert!(matches!(
        connect_none()
            .await?
            .umount_all(["hello-world:0.0.1", "crashing:0.0.1"])
            .await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_stats() -> Result<()> {
    assert!(matches!(
        connect_none()
            .await?
            .container_stats("hello_world:0.0.1")
            .await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
    Ok(())
}
