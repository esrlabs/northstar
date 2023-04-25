use std::iter;

use anyhow::Result;
use futures::{SinkExt, StreamExt};

use northstar_runtime::api::{
    self,
    model::{self, Container},
};
use northstar_tests::runtime_test;
use tokio::{net::UnixStream, time::Duration};

// Connect with exact version
#[runtime_test]
async fn api_version_match() -> Result<()> {
    let mut connection = api::codec::framed(
        UnixStream::connect(&northstar_tests::runtime::console_url().path()).await?,
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
    client.list().await?;
    Ok(())
}

// Connect too low version
#[runtime_test]
async fn api_version_low() -> Result<()> {
    let mut connection = api::codec::framed(
        UnixStream::connect(&northstar_tests::runtime::console_url().path()).await?,
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
        UnixStream::connect(&northstar_tests::runtime::console_url().path()).await?,
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
        UnixStream::connect(&northstar_tests::runtime::console_url().path()).await?,
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
    let io = UnixStream::connect(&northstar_tests::runtime::console_url().path()).await?;
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
    let io = UnixStream::connect(&northstar_tests::runtime::console_url().path()).await?;
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
