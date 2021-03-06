// Copyright (c) 2020 ESRLabs
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

use super::{
    codec::{self, framed},
    model::{
        self, Connect, Container, ContainerData, ContainerError, Message, MountResult,
        Notification, RepositoryId, Request, Response,
    },
};
use crate::common::{name::InvalidNameChar, version::Version};
use futures::{SinkExt, Stream, StreamExt};
use log::debug;
use std::{
    collections::{HashSet, VecDeque},
    convert::TryInto,
    path::Path,
    pin::Pin,
    task::Poll,
};
use thiserror::Error;
use tokio::{
    fs, io,
    net::{TcpStream, UnixStream},
    time,
};
use tokio_util::either::Either;
use url::Url;

const SCHEME_TCP: &str = "tcp";
const SCHEME_UNIX: &str = "unix";

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0:?}")]
    Io(#[from] io::Error),
    #[error("Timeout")]
    Timeout,
    #[error("Client is stopped")]
    Stopped,
    #[error("Protocol error")]
    Protocol,
    #[error("Api error: {0:?}")]
    Api(super::model::Error),
    #[error("Invalid console address {0}, use either tcp://... or unix://...")]
    InvalidConsoleAddress(String),
    #[error("Notification consumer lagged")]
    LaggedNotifications,
    #[error("Invalid name {0}")]
    Name(InvalidNameChar),
    #[error("Invalid container {0}")]
    Container(ContainerError),
}

/// Client for a Northstar runtime instance.
///
/// ```no_run
/// use futures::StreamExt;
/// use tokio::time::Duration;
/// use northstar::api::client::Client;
/// use northstar::common::version::Version;
///
/// #[tokio::main]
/// async fn main() {
///     let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap(), None, Duration::from_secs(10)).await.unwrap();
///     client.start("hello", &Version::parse("0.0.1").unwrap()).await.expect("Failed to start \"hello\"");
///     while let Some(notification) = client.next().await {
///         println!("{:?}", notification);
///     }
/// }
/// ```
pub struct Client {
    /// Connection to the runtime
    connection: codec::Framed<Either<TcpStream, UnixStream>>,
    /// Buffer notifications received during request response communication
    notifications: Option<VecDeque<Notification>>,
    /// Flag if the client is stopped
    fused: bool,
}

/// Northstar console connection
pub type Connection = codec::Framed<Either<TcpStream, UnixStream>>;

impl<'a> Client {
    /// Connect and return a raw stream and sink interface. See codec for details
    pub async fn connect(
        url: &Url,
        notifications: Option<usize>,
        timeout: time::Duration,
    ) -> Result<Connection, Error> {
        let mut connection = match url.scheme() {
            SCHEME_TCP => {
                let addresses = url.socket_addrs(|| Some(4200))?;
                let address = addresses
                    .first()
                    .ok_or_else(|| Error::InvalidConsoleAddress(url.to_string()))?;
                let stream = time::timeout(timeout, TcpStream::connect(address))
                    .await
                    .map_err(|_| Error::Timeout)??;
                framed(Either::Left(stream))
            }
            SCHEME_UNIX => {
                let stream = time::timeout(timeout, UnixStream::connect(url.path()))
                    .await
                    .map_err(|_| Error::Timeout)??;
                framed(Either::Right(stream))
            }
            _ => return Err(Error::InvalidConsoleAddress(url.to_string())),
        };

        // Send connect message
        let connect = Connect::Connect {
            version: model::version(),
            subscribe_notifications: notifications.is_some(),
        };
        connection
            .send(Message::new_connect(connect))
            .await
            .map_err(Error::Io)?;

        // Wait for conack
        let connect = time::timeout(timeout, connection.next());
        match connect.await {
            Ok(Some(Ok(message))) => match message {
                Message::Connect(Connect::ConnectAck) => Ok(connection),
                _ => {
                    debug!(
                        "Received invalid message {:?} while waiting for connack",
                        message
                    );
                    Err(Error::Protocol)
                }
            },
            Ok(Some(Err(e))) => Err(Error::Io(e)),
            Ok(None) => {
                debug!("Connection closed while waiting for connack");
                Err(Error::Protocol)
            }
            Err(_) => {
                debug!("Timeout waiting for connack");
                Err(Error::Protocol)
            }
        }
    }

    /// Create a new northstar client and connect to a runtime instance running on `host`.
    pub async fn new(
        url: &Url,
        notifications: Option<usize>,
        timeout: time::Duration,
    ) -> Result<Client, Error> {
        let connection = time::timeout(timeout, Self::connect(url, notifications, timeout))
            .await
            .map_err(|_| Error::Timeout)??;

        debug!("Connected to {}", url);

        Ok(Client {
            connection,
            notifications: notifications.map(VecDeque::with_capacity),
            fused: false,
        })
    }

    /// Perform a request response sequence
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use tokio::time::Duration;
    /// # use northstar::api::client::Client;
    /// # use northstar::api::model::Request::Containers;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// let response = client.request(Containers).await.expect("Failed to request container list");
    /// println!("{:?}", response);
    /// # }
    /// ```
    pub async fn request(&mut self, request: Request) -> Result<Response, Error> {
        self.fused()?;

        let message = Message::new_request(request);
        self.connection.send(message).await.map_err(|e| {
            self.fuse();
            Error::Io(e)
        })?;
        loop {
            match self.connection.next().await {
                Some(Ok(message)) => match message {
                    Message::Response(r) => break Ok(r),
                    Message::Notification(notification) => self.queue_notification(notification)?,
                    _ => {
                        self.fuse();
                        break Err(Error::Protocol);
                    }
                },
                Some(Err(e)) => {
                    self.fuse();
                    break Err(Error::Io(e));
                }
                None => {
                    self.fuse();
                    break Err(Error::Stopped);
                }
            }
        }
    }

    /// Request a list of installed containers
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use tokio::time::Duration;
    /// # use northstar::api::client::Client;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// let containers = client.containers().await.expect("Failed to request container list");
    /// println!("{:#?}", containers);
    /// # }
    /// ```
    pub async fn containers(&mut self) -> Result<Vec<ContainerData>, Error> {
        match self.request(Request::Containers).await? {
            Response::Containers(containers) => Ok(containers),
            Response::Err(e) => Err(Error::Api(e)),
            _ => Err(Error::Protocol),
        }
    }

    /// Request a list of repositories
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use tokio::time::Duration;
    /// # use northstar::api::client::Client;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// let repositories = client.repositories().await.expect("Failed to request repository list");
    /// println!("{:#?}", repositories);
    /// # }
    /// ```
    pub async fn repositories(&mut self) -> Result<HashSet<RepositoryId>, Error> {
        match self.request(Request::Repositories).await? {
            Response::Err(e) => Err(Error::Api(e)),
            Response::Repositories(repositories) => Ok(repositories),
            _ => Err(Error::Protocol),
        }
    }

    /// Start container with name
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use std::time::Duration;
    /// # use northstar::api::client::Client;
    /// # use northstar::common::version::Version;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// client.start("hello", &Version::parse("0.0.1").unwrap()).await.expect("Failed to start \"hello\"");
    /// // Print start notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn start(&mut self, name: &str, version: &Version) -> Result<(), Error> {
        match self
            .request(Request::Start(Container::new(
                name.try_into().map_err(Error::Name)?,
                version.clone(),
            )))
            .await?
        {
            Response::Ok(()) => Ok(()),
            Response::Err(e) => Err(Error::Api(e)),
            _ => Err(Error::Protocol),
        }
    }

    /// Stop container with name
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use tokio::time::Duration;
    /// # use northstar::api::client::Client;
    /// # use northstar::common::version::Version;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// client.stop("hello", &Version::parse("0.0.1").unwrap(), Duration::from_secs(3)).await.expect("Failed to start \"hello\"");
    /// // Print stop notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn stop(
        &mut self,
        name: &str,
        version: &Version,
        timeout: time::Duration,
    ) -> Result<(), Error> {
        match self
            .request(Request::Stop(
                Container::new(name.try_into().map_err(Error::Name)?, version.clone()),
                timeout.as_secs(),
            ))
            .await?
        {
            Response::Ok(()) => Ok(()),
            Response::Err(e) => Err(Error::Api(e)),
            _ => Err(Error::Protocol),
        }
    }

    /// Install a npk
    ///
    /// ```no_run
    /// # use northstar::api::client::Client;
    /// # use std::time::Duration;
    /// # use std::path::Path;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// let npk = Path::new("test.npk");
    /// client.install(&npk, "default").await.expect("Failed to install \"test.npk\" into repository \"default\"");
    /// # }
    /// ```
    pub async fn install(&mut self, npk: &Path, repository: &str) -> Result<(), Error> {
        self.fused()?;
        let mut file = fs::File::open(npk).await.map_err(Error::Io)?;
        let size = file.metadata().await.unwrap().len();
        let request = Request::Install(repository.into(), size);
        let message = Message::new_request(request);
        self.connection.send(message).await.map_err(|_| {
            self.fuse();
            Error::Stopped
        })?;

        io::copy(&mut file, &mut self.connection)
            .await
            .map_err(|e| {
                self.fuse();
                Error::Io(e)
            })?;

        loop {
            match self.connection.next().await {
                Some(Ok(message)) => match message {
                    Message::Response(r) => match r {
                        Response::Ok(_) => break Ok(()),
                        Response::Err(e) => break Err(Error::Api(e)),
                        _ => {
                            self.fuse();
                            break Err(Error::Protocol);
                        }
                    },
                    Message::Notification(notification) => self.queue_notification(notification)?,
                    _ => break Err(Error::Protocol),
                },
                Some(Err(e)) => {
                    self.fuse();
                    break Err(Error::Io(e));
                }
                None => {
                    self.fuse();
                    break Err(Error::Stopped);
                }
            }
        }
    }

    /// Uninstall a npk
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use std::time::Duration;
    /// # use northstar::api::client::Client;
    /// # use northstar::common::version::Version;
    /// # use std::path::Path;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// client.uninstall("hello", &Version::parse("0.0.1").unwrap()).await.expect("Failed to uninstall \"hello\"");
    /// // Print stop notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn uninstall(&mut self, name: &str, version: &Version) -> Result<(), Error> {
        match self
            .request(Request::Uninstall(Container::new(
                name.to_string().try_into().map_err(Error::Name)?,
                version.clone(),
            )))
            .await?
        {
            Response::Ok(()) => Ok(()),
            Response::Err(e) => Err(Error::Api(e)),
            _ => {
                self.fuse();
                Err(Error::Protocol)
            }
        }
    }

    /// Stop the runtime
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        match self.request(Request::Shutdown).await? {
            Response::Ok(()) => Ok(()),
            Response::Err(e) => Err(Error::Api(e)),
            _ => {
                self.fuse();
                Err(Error::Protocol)
            }
        }
    }

    /// Mount a list of containers
    /// ```no_run
    /// # use northstar::api::client::Client;
    /// # use std::time::Duration;
    /// # use northstar::common::version::Version;
    /// # use std::path::Path;
    /// # use std::convert::TryInto;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// let container = "test:0.0.2".try_into().unwrap();
    /// client.mount(vec!(container)).await.expect("Failed to mount");
    /// # }
    /// ```
    pub async fn mount<I>(&mut self, containers: I) -> Result<Vec<MountResult>, Error>
    where
        I: 'a + IntoIterator<Item = Container>,
    {
        self.fused()?;
        match self
            .request(Request::Mount(containers.into_iter().collect()))
            .await?
        {
            Response::Mount(mounts) => Ok(mounts),
            Response::Err(e) => Err(Error::Api(e)),
            _ => {
                self.fuse();
                Err(Error::Protocol)
            }
        }
    }

    /// Umount a mounted container
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use std::path::Path;
    /// # use northstar::api::client::Client;
    /// # use northstar::common::version::Version;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// client.umount("hello", &Version::parse("0.0.1").unwrap()).await.expect("Failed to unmount \"hello\"");
    /// # }
    /// ```
    pub async fn umount(&mut self, name: &str, version: &Version) -> Result<(), Error> {
        match self
            .request(Request::Umount(Container::new(
                name.to_string().try_into().map_err(Error::Name)?,
                version.clone(),
            )))
            .await?
        {
            Response::Ok(()) => Ok(()),
            Response::Err(e) => Err(Error::Api(e)),
            _ => {
                self.fuse();
                Err(Error::Protocol)
            }
        }
    }

    /// Store a notification in the notification queue
    fn queue_notification(&mut self, notification: Notification) -> Result<(), Error> {
        if let Some(notifications) = &mut self.notifications {
            if notifications.len() == notifications.capacity() {
                self.fuse();
                Err(Error::LaggedNotifications)
            } else {
                notifications.push_back(notification);
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    /// Set the fused flag
    fn fuse(&mut self) {
        self.fused = true;
    }

    /// Return Error::Stopped if the client is fused
    fn fused(&self) -> Result<(), Error> {
        if self.fused {
            Err(Error::Stopped)
        } else {
            Ok(())
        }
    }
}

/// Stream notifications
///
/// ```no_run
/// use futures::StreamExt;
/// use std::time::Duration;
/// use northstar::api::client::Client;
/// use northstar::common::version::Version;
///
/// #[tokio::main]
/// async fn main() {
///     let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap(), Some(10), Duration::from_secs(10)).await.unwrap();
///     client.start("hello", &Version::parse("0.0.1").unwrap()).await.expect("Failed to start \"hello\"");
///     while let Some(notification) = client.next().await {
///         println!("{:?}", notification);
///     }
/// }
/// ```
impl Stream for Client {
    type Item = Result<Notification, io::Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if self.fused {
            return Poll::Ready(None);
        }

        if let Some(n) = self.notifications.as_mut().and_then(|n| n.pop_front()) {
            Poll::Ready(Some(Ok(n)))
        } else {
            match self.connection.poll_next_unpin(cx) {
                Poll::Ready(r) => match r {
                    Some(Ok(message)) => match message {
                        Message::Notification(n) => Poll::Ready(Some(Ok(n))),
                        _ => unreachable!(),
                    },
                    Some(Err(e)) => Poll::Ready(Some(Err(e))),
                    None => Poll::Ready(None),
                },
                Poll::Pending => Poll::Pending,
            }
        }
    }
}
