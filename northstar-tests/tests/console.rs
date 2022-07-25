use std::{iter, path::Path};

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use northstar_client::{error::RequestError, Client};
use northstar_runtime::api::{
    self,
    model::{self, Container},
};
use northstar_tests::{runtime::client, runtime_test};
use tokio::{net::UnixStream, time::Duration};

/// Connect a client to the runtime console without any permission configured.
async fn connect_none() -> Result<northstar_client::Client<UnixStream>> {
    let io = UnixStream::connect(&northstar_tests::runtime::console_none().path()).await?;
    northstar_client::Client::new(io, None, Duration::from_secs(10))
        .await
        .context("failed to connect to the runtime")
}

// Connect with exact version
#[runtime_test]
async fn api_version_match() -> Result<()> {
    let mut connection = api::codec::framed(
        UnixStream::connect(&northstar_tests::runtime::console_none().path()).await?,
    );
    let connect_message = api::model::Message::Connect {
        connect: api::model::Connect {
            version: api::VERSION,
            subscribe_notifications: false,
        },
    };
    connection.send(connect_message.clone()).await?;
    match connection.next().await.unwrap().unwrap() {
        model::Message::ConnectAck { .. } => (),
        _ => panic!("unexpected message"),
    }
    client().list().await?;
    Ok(())
}

// Connect too low version
#[runtime_test]
async fn api_version_low() -> Result<()> {
    let mut connection = api::codec::framed(
        UnixStream::connect(&northstar_tests::runtime::console_none().path()).await?,
    );
    let mut version = api::VERSION.clone();
    version.minor -= 1;
    let connect_message = api::model::Message::Connect {
        connect: api::model::Connect {
            version,
            subscribe_notifications: false,
        },
    };
    connection.send(connect_message.clone()).await?;
    match connection.next().await.unwrap().unwrap() {
        model::Message::ConnectNack { .. } => Ok(()),
        _ => panic!("unexpected message"),
    }
}

// Connect with higher version
#[runtime_test]
async fn api_version_higher() -> Result<()> {
    let mut connection = api::codec::framed(
        UnixStream::connect(&northstar_tests::runtime::console_none().path()).await?,
    );
    let mut version = api::VERSION.clone();
    version.patch += 1;
    let connect_message = api::model::Message::Connect {
        connect: api::model::Connect {
            version,
            subscribe_notifications: false,
        },
    };
    connection.send(connect_message.clone()).await?;
    match connection.next().await.unwrap().unwrap() {
        model::Message::ConnectAck { .. } => Ok(()),
        _ => panic!("unexpected message"),
    }
}

// Connect with incompatibel minor version
#[runtime_test]
async fn api_version_minor_version_low() -> Result<()> {
    let mut connection = api::codec::framed(
        UnixStream::connect(&northstar_tests::runtime::console_none().path()).await?,
    );
    let mut version = api::VERSION.clone();
    version.minor -= 1;
    let connect_message = api::model::Message::Connect {
        connect: api::model::Connect {
            version,
            subscribe_notifications: false,
        },
    };
    connection.send(connect_message.clone()).await?;
    match connection.next().await.unwrap().unwrap() {
        model::Message::ConnectNack { .. } => Ok(()),
        _ => panic!("unexpected message"),
    }
}

/// Expect the connection to be closed if a request with a too long line is sent.
#[runtime_test]
async fn too_long_line() -> Result<()> {
    let timeout = Duration::from_secs(10);
    let io = UnixStream::connect(&northstar_tests::runtime::console_full().path()).await?;
    let mut client = northstar_client::Client::new(io, None, timeout).await?;

    // The default json line limit is 512K
    let container = Container::try_from("hello-world:0.0.1").unwrap();
    let containers = iter::repeat(container).take(100000).collect();

    match client.request(model::Request::Mount { containers }).await {
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
        .request(model::Request::Install {
            repository: "mem".into(),
            size: 999999999,
        })
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
        Err(RequestError::PermissionDenied)
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_repositories() -> Result<()> {
    assert!(matches!(
        connect_none().await?.repositories().await,
        Err(RequestError::PermissionDenied)
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_start() -> Result<()> {
    assert!(matches!(
        connect_none().await?.start("hello-world:0.0.1").await,
        Err(RequestError::PermissionDenied)
    ));
    assert!(matches!(
        connect_none()
            .await?
            .start_with_args("hello-world:0.0.1", ["--help"])
            .await,
        Err(RequestError::PermissionDenied)
    ));
    assert!(matches!(
        connect_none()
            .await?
            .start_with_args_env("hello-world:0.0.1", ["--help"], [("HELLO", "YOU")])
            .await,
        Err(RequestError::PermissionDenied)
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_kill() -> Result<()> {
    assert!(matches!(
        connect_none().await?.kill("hello-world:0.0.1", 15).await,
        Err(RequestError::PermissionDenied)
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_install() -> Result<()> {
    assert!(matches!(
        dbg!(
            connect_none()
                .await?
                .install_file(Path::new("/etc/hosts"), "mem")
                .await
        ),
        Err(RequestError::PermissionDenied)
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_uninstall() -> Result<()> {
    assert!(matches!(
        connect_none().await?.uninstall("hello-world:0.0.1").await,
        Err(RequestError::PermissionDenied)
    ));
    Result::<()>::Ok(())
}

#[runtime_test]
async fn permissions_mount() -> Result<()> {
    assert!(matches!(
        connect_none().await?.mount("hello-world:0.0.1").await,
        Err(RequestError::PermissionDenied)
    ));

    assert!(matches!(
        connect_none()
            .await?
            .mount_all(["hello-world:0.0.1", "crashing:0.0.1"])
            .await,
        Err(RequestError::PermissionDenied)
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_umount() -> Result<()> {
    assert!(matches!(
        connect_none().await?.umount("hello-world:0.0.1").await,
        Err(RequestError::PermissionDenied)
    ));

    assert!(matches!(
        connect_none()
            .await?
            .umount_all(["hello-world:0.0.1", "crashing:0.0.1"])
            .await,
        Err(RequestError::PermissionDenied)
    ));
    Ok(())
}

#[runtime_test]
async fn permissions_inspect() -> Result<()> {
    let mut console = connect_none().await?;
    assert!(matches!(
        Client::inspect(&mut console, "hello_world:0.0.1").await,
        Err(RequestError::PermissionDenied)
    ));
    Ok(())
}
