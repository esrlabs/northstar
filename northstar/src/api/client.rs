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

use futures::{SinkExt, Stream, StreamExt};
use log::info;
use npk::manifest::Version;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    pin::Pin,
    task::Poll,
};
use thiserror::Error;
use tokio::{
    fs,
    io::{self, AsyncRead, AsyncWrite},
    net::{TcpStream, UnixStream},
    select,
    sync::{mpsc, oneshot},
    task, time,
};
use url::Url;

use super::{
    codec::framed,
    model::{
        Container, ContainerData, Message, MountResult, Notification, Payload, Repository,
        RepositoryId, Request, Response,
    },
};

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

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
    #[error("Pending request")]
    PendingRequest,
    #[error("Api error: {0:?}")]
    Api(super::model::Error),
    #[error("Invalid console address {0}, use either tcp://... or unix:...")]
    InvalidConsoleAddress(String),
}

/// Client for a Northstar runtime instance.
///
/// ```no_run
/// use futures::StreamExt;
/// use northstar::api::client::Client;
/// # use npk::manifest::Version;
///
/// #[tokio::main]
/// async fn main() {
///     let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap()).await.unwrap();
///     client.start("hello", &Version::parse("0.0.1").unwrap()).await.expect("Failed to start \"hello\"");
///     while let Some(notification) = client.next().await {
///         println!("{:?}", notification);
///     }
/// }
/// ```
pub struct Client {
    notification_rx: mpsc::Receiver<Result<Notification, Error>>,
    request_tx: mpsc::Sender<(ClientRequest, oneshot::Sender<Result<Response, Error>>)>,
}

enum ClientRequest {
    Request(Request),
    Install(PathBuf, String),
}

impl<'a> Client {
    /// Create a new northstar client and connect to a runtime instance running on `host`.
    pub async fn new(url: &Url) -> Result<Client, Error> {
        let (notification_tx, notification_rx) = mpsc::channel(10);
        let (request_tx, mut request_rx) =
            mpsc::channel::<(ClientRequest, oneshot::Sender<Result<Response, Error>>)>(10);
        let mut response_tx = Option::<oneshot::Sender<Result<Response, Error>>>::None;

        let mut connection = match url.scheme() {
            "tcp" => {
                let addresses = url.socket_addrs(|| Some(4200))?;
                let address = addresses
                    .first()
                    .ok_or_else(|| Error::InvalidConsoleAddress(url.to_string()))?;
                framed(
                    Box::new(TcpStream::connect(address).await.map_err(Error::Io)?)
                        as Box<dyn AsyncReadWrite>,
                )
            }
            "unix" => framed(
                Box::new(UnixStream::connect(url.path()).await.map_err(Error::Io)?)
                    as Box<dyn AsyncReadWrite>,
            ),
            _ => return Err(Error::InvalidConsoleAddress(url.to_string())),
        };

        task::spawn(async move {
            loop {
                select! {
                    message = connection.next() => {
                        match message {
                            Some(Ok(message)) => match message.payload {
                                Payload::Request(_) => break Err(Error::Protocol),
                                Payload::Response(r) => {
                                    if let Some(r_tx) = response_tx.take() {
                                        r_tx.send(Ok(r)).ok();
                                    } else {
                                        break Err(Error::Protocol);
                                    }
                                }
                                Payload::Notification(n) => drop(notification_tx.try_send(Ok(n))),
                            },
                            Some(Err(e)) => break Err(Error::Io(e)),
                            None => {
                                    info!("Connection closed");
                                    break Ok(());
                            }
                        }
                    }
                    request = request_rx.recv() => {
                        if let Some((request, r_tx)) = request {
                            if response_tx.is_some() {
                                r_tx.send(Err(Error::PendingRequest)).ok();
                            } else {
                                match request {
                                    ClientRequest::Request(request) => {
                                        match connection.send(Message::new_request(request)).await {
                                            Ok(_) => response_tx = Some(r_tx), // Store the reponse tx part
                                            Err(e) => drop(r_tx.send(Err(Error::Io(e)))),
                                        }
                                    }
                                    ClientRequest::Install(npk, repository) => {
                                        let mut file = fs::File::open(npk).await.expect("Failed to open"); // TODO
                                        let size = file.metadata().await.unwrap().len();
                                        let request = Request::Install(repository, size);
                                        match connection.send(Message::new_request(request)).await {
                                            Ok(_) => response_tx = Some(r_tx), // Store the reponse tx part
                                            Err(e) => drop(r_tx.send(Err(Error::Io(e)))),
                                        }
                                        io::copy(&mut file, &mut connection).await?;
                                    }
                                }
                            }
                        } else {
                            break Ok(());
                        }
                    }
                }
            }
        });

        Ok(Client {
            notification_rx,
            request_tx,
        })
    }

    /// Perform a request reponse sequence
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use northstar::api::client::Client;
    /// # use northstar::api::model::Request::Containers;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap()).await.unwrap();
    /// let response = client.request(Containers).await.expect("Failed to request container list");
    /// println!("{:?}", response);
    /// # }
    /// ```
    pub async fn request(&self, request: Request) -> Result<Response, Error> {
        let (tx, rx) = oneshot::channel::<Result<Response, Error>>();
        self.request_tx
            .send((ClientRequest::Request(request), tx))
            .await
            .map_err(|_| Error::Stopped)?;
        rx.await.map_err(|_| Error::Stopped)?
    }

    /// Request a list of installed containers
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use northstar::api::client::Client;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap()).await.unwrap();
    /// let containers = client.containers().await.expect("Failed to request container list");
    /// println!("{:#?}", containers);
    /// # }
    /// ```
    pub async fn containers(&self) -> Result<Vec<ContainerData>, Error> {
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
    /// # use northstar::api::client::Client;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap()).await.unwrap();
    /// let repositories = client.repositories().await.expect("Failed to request repository list");
    /// println!("{:#?}", repositories);
    /// # }
    /// ```
    pub async fn repositories(&self) -> Result<HashMap<RepositoryId, Repository>, Error> {
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
    /// # use northstar::api::client::Client;
    /// # use npk::manifest::Version;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap()).await.unwrap();
    /// client.start("hello", &Version::parse("0.0.1").unwrap()).await.expect("Failed to start \"hello\"");
    /// // Print start notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn start(&self, name: &str, version: &Version) -> Result<(), Error> {
        match self
            .request(Request::Start(Container::new(
                name.to_string(),
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
    /// # use northstar::api::client::Client;
    /// # use npk::manifest::Version;
    /// # use std::time::Duration;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap()).await.unwrap();
    /// client.stop("hello", &Version::parse("0.0.1").unwrap(), Duration::from_secs(3)).await.expect("Failed to start \"hello\"");
    /// // Print stop notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn stop(
        &self,
        name: &str,
        version: &Version,
        timeout: time::Duration,
    ) -> Result<(), Error> {
        match self
            .request(Request::Stop(
                Container::new(name.to_string(), version.clone()),
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
    /// # use std::path::Path;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap()).await.unwrap();
    /// let npk = Path::new("test.npk");
    /// client.install(&npk, "default").await.expect("Failed to install \"test.npk\" into repository \"default\"");
    /// # }
    /// ```
    pub async fn install(&self, npk: &Path, repository: &str) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel::<Result<Response, Error>>();
        self.request_tx
            .send((
                ClientRequest::Install(npk.to_owned(), repository.to_owned()),
                tx,
            ))
            .await
            .map_err(|_| Error::Stopped)?;
        match rx.await.map_err(|_| Error::Stopped)?? {
            Response::Ok(()) => Ok(()),
            Response::Err(e) => Err(Error::Api(e)),
            _ => Err(Error::Protocol),
        }
    }

    /// Uninstall a npk
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use northstar::api::client::Client;
    /// # use npk::manifest::Version;
    /// # use std::path::Path;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap()).await.unwrap();
    /// client.uninstall("hello", &Version::parse("0.0.1").unwrap()).await.expect("Failed to uninstall \"hello\"");
    /// // Print stop notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn uninstall(&self, name: &str, version: &Version) -> Result<(), Error> {
        match self
            .request(Request::Uninstall(Container::new(
                name.to_string(),
                version.clone(),
            )))
            .await?
        {
            Response::Ok(()) => Ok(()),
            Response::Err(e) => Err(Error::Api(e)),
            _ => Err(Error::Protocol),
        }
    }

    /// Stop the runtime
    pub async fn shutdown(&self) -> Result<(), Error> {
        match self.request(Request::Shutdown).await? {
            Response::Ok(()) => Ok(()),
            Response::Err(e) => Err(Error::Api(e)),
            _ => Err(Error::Protocol),
        }
    }

    /// Mount a list of containers
    /// ```no_run
    /// # use northstar::api::client::Client;
    /// # use npk::manifest::Version;
    /// # use std::path::Path;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap()).await.unwrap();
    /// let version = Version::parse("0.0.2").unwrap();
    /// let to_mount = vec!(("hello", &version), ("test", &version));
    /// client.mount(to_mount).await.expect("Failed to mount");
    /// # }
    /// ```
    pub async fn mount<I: 'a + IntoIterator<Item = (&'a str, &'a Version)>>(
        &self,
        containers: I,
    ) -> Result<Vec<(Container, MountResult)>, Error> {
        let containers = containers
            .into_iter()
            .map(|(name, version)| Container::new(name.to_string(), version.clone()))
            .collect();
        match self.request(Request::Mount(containers)).await? {
            Response::Mount(mounts) => Ok(mounts),
            Response::Ok(_) => unreachable!(),
            Response::Err(e) => Err(Error::Api(e)),
            _ => Err(Error::Protocol),
        }
    }

    /// Umount a mounted container
    ///
    /// ```no_run
    /// # use northstar::api::client::Client;
    /// # use npk::manifest::Version;
    /// # use std::path::Path;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// #   let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap()).await.unwrap();
    /// client.umount("hello", &Version::parse("0.0.1").unwrap()).await.expect("Failed to unmount \"hello\"");
    /// # }
    /// ```
    pub async fn umount(&self, name: &str, version: &Version) -> Result<(), Error> {
        match self
            .request(Request::Umount(Container::new(
                name.to_string(),
                version.clone(),
            )))
            .await?
        {
            Response::Ok(()) => Ok(()),
            Response::Err(e) => Err(Error::Api(e)),
            _ => Err(Error::Protocol),
        }
    }
}

/// Stream notifications
///
/// ```no_run
/// use futures::StreamExt;
/// use northstar::api::client::Client;
/// use npk::manifest::Version;
///
/// #[tokio::main]
/// async fn main() {
///     let mut client = Client::new(&url::Url::parse("tcp://localhost:4200").unwrap()).await.unwrap();
///     client.start("hello", &Version::parse("0.0.1").unwrap()).await.expect("Failed to start \"hello\"");
///     while let Some(notification) = client.next().await {
///         println!("{:?}", notification);
///     }
/// }
/// ```
impl Stream for Client {
    type Item = Result<Notification, Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.notification_rx).poll_recv(cx)
    }
}
