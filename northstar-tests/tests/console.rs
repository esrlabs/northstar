use std::path::Path;

use anyhow::{Context, Result};
use api::{client::Error as ClientError, model::Error as ModelError};
use futures::{SinkExt, StreamExt};
use northstar::api::{
    self,
    model::{self, ConnectNack},
};
use northstar_tests::test;
use tokio::{net::UnixStream, time::Duration};

/// Connect a client to the runtime console without any permission configured.
async fn connect_none() -> Result<api::client::Client<UnixStream>> {
    let io = UnixStream::connect(&northstar_tests::runtime::console_none().path()).await?;
    dbg!(&io);
    api::client::Client::new(io, None, Duration::from_secs(10))
        .await
        .context("Failed to connect to the runtime")
}

// Verify that the client() reject a version mismatch in Connect
test!(api_version, {
    let mut connection = api::codec::Framed::new(
        UnixStream::connect(&northstar_tests::runtime::console_none().path()).await?,
    );

    // Send a connect with an version unequal to the one defined in the model
    let mut version = api::model::version();
    version.patch += 1;

    let connect = api::model::Connect::new_connect(version, false);
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

test!(notifications, {
    let io = UnixStream::connect(&northstar_tests::runtime::console_none().path()).await?;
    assert!(
        api::client::Client::new(io, Some(10), Duration::from_secs(10))
            .await
            .is_err()
    );
});

test!(permission_containers, {
    assert!(matches!(
        connect_none().await?.containers().await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
});

test!(permission_repositories, {
    assert!(matches!(
        connect_none().await?.repositories().await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
});

test!(permission_start, {
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
});

test!(permission_kill, {
    assert!(matches!(
        connect_none().await?.kill("hello-world:0.0.1", 15).await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
});

test!(permission_install, {
    assert!(matches!(
        connect_none()
            .await?
            .install(Path::new("/etc/hosts"), "mem")
            .await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
});

test!(permission_uninstall, {
    assert!(matches!(
        connect_none().await?.uninstall("hello-world:0.0.1").await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
});

test!(permission_mount, {
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
});

test!(permission_umount, {
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
});

test!(permission_stats, {
    assert!(matches!(
        connect_none()
            .await?
            .container_stats("hello_world:0.0.1")
            .await,
        Err(ClientError::Runtime(ModelError::PermissionDenied { .. }))
    ));
});
