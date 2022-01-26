use super::{
    codec,
    model::{
        self, Connect, ConnectNack, Container, ContainerData, ContainerStats, Message, MountResult,
        Notification, RepositoryId, Request, Response, Token, UmountResult, VerificationResult,
    },
};
use crate::common::{
    container,
    non_nul_string::{InvalidNulChar, NonNulString},
};
use futures::{SinkExt, Stream, StreamExt};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::{Infallible, TryInto},
    iter::empty,
    os::unix::prelude::FromRawFd,
    path::Path,
    pin::Pin,
    task::Poll,
};
use thiserror::Error;
use tokio::{
    fs,
    io::{self, AsyncRead, AsyncWrite, BufWriter},
    time,
};

/// Default buffer size for installation transfers
const BUFFER_SIZE: usize = 1024 * 1024;

/// API error
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0:?}")]
    Io(#[from] io::Error),
    #[error("timeout")]
    Timeout,
    #[error("client is stopped")]
    Stopped,
    #[error("runtime error: {0:?}")]
    Runtime(model::Error),
    #[error("notification consumer lagged")]
    LaggedNotifications,
    #[error("invalid container {0}")]
    Container(container::Error),
    #[error("invalid string {0}")]
    String(InvalidNulChar),
    #[error("infalliable")]
    Infalliable,
    #[error("invalid file descriptor from env NORTHSTAR_CONSOLE")]
    FromEnv,
}

impl From<container::Error> for Error {
    fn from(e: container::Error) -> Error {
        Error::Container(e)
    }
}

impl From<InvalidNulChar> for Error {
    fn from(e: InvalidNulChar) -> Self {
        Error::String(e)
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        Error::Infalliable
    }
}

/// Client for a Northstar runtime instance.
///
/// ```no_run
/// use futures::StreamExt;
/// use tokio::time::Duration;
/// use northstar::api::client::Client;
/// use northstar::common::version::Version;
///
/// # #[tokio::main(flavor = "current_thread")]
/// async fn main() {
///     let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
///     client.start("hello:0.0.1").await.expect("failed to start \"hello\"");
///     while let Some(notification) = client.next().await {
///         println!("{:?}", notification);
///     }
/// }
/// ```
pub struct Client<T> {
    /// Connection to the runtime
    connection: codec::Framed<T>,
    /// Buffer notifications received during request response communication
    notifications: Option<VecDeque<Notification>>,
    /// Flag if the client is stopped
    fused: bool,
}

/// Northstar console connection
pub type Connection<T> = codec::Framed<T>;

/// Connect and return a raw stream and sink interface. See codec for details
pub async fn connect<T: AsyncRead + AsyncWrite + Unpin>(
    io: T,
    notifications: Option<usize>,
    timeout: time::Duration,
) -> Result<Connection<T>, Error> {
    let mut connection = codec::Framed::new(io);
    let subscribe_notifications = notifications.is_some();
    let version = model::version();

    // Send connect message
    let connect = Connect::Connect {
        version,
        subscribe_notifications,
    };
    connection
        .send(Message::Connect { connect })
        .await
        .map_err(Error::Io)?;

    // Wait for conack
    let connect = time::timeout(timeout, connection.next());
    let message = match connect.await {
        Ok(Some(Ok(message))) => message,
        Ok(Some(Err(e))) => return Err(Error::Io(e)),
        Ok(None) => {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Connection closed",
            )))
        }
        Err(_) => return Err(Error::Timeout),
    };

    // Expect a connect message
    let connect = match message {
        Message::Connect { connect } => connect,
        _ => unreachable!("expecting connect"),
    };

    match connect {
        Connect::Ack { .. } => Ok(connection),
        Connect::Nack { error } => match error {
            ConnectNack::InvalidProtocolVersion { .. } => Err(Error::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "Protocol version unsupported",
            ))),
            ConnectNack::PermissionDenied => Err(Error::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Permission denied",
            ))),
        },
        _ => unreachable!("expecting connect ack or nack"),
    }
}

impl Client<tokio::net::UnixStream> {
    /// Tries to create a client by accessing `NORTHSTAR_CONSOLE` env variable
    pub async fn from_env(
        notifications: Option<usize>,
        timeout: time::Duration,
    ) -> Result<Self, Error> {
        let fd = std::env::var("NORTHSTAR_CONSOLE")
            .map_err(|_| Error::FromEnv)?
            .parse::<i32>()
            .map_err(|_| Error::FromEnv)?;

        let std = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        std.set_nonblocking(true)?;
        let io = tokio::net::UnixStream::from_std(std)?;
        Client::new(io, notifications, timeout).await
    }
}

impl<'a, T: AsyncRead + AsyncWrite + Unpin> Client<T> {
    /// Create a new northstar client and connect to a runtime instance running on `host`.
    pub async fn new(
        io: T,
        notifications: Option<usize>,
        timeout: time::Duration,
    ) -> Result<Client<T>, Error> {
        let connection = time::timeout(timeout, connect(io, notifications, timeout))
            .await
            .map_err(|_| Error::Timeout)??;

        Ok(Client {
            connection,
            notifications: notifications.map(VecDeque::with_capacity),
            fused: false,
        })
    }

    /// Convert client into a connection
    pub fn framed(self) -> Connection<T> {
        self.connection
    }

    /// Perform a request response sequence
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use tokio::time::Duration;
    /// # use northstar::api::client::Client;
    /// # use northstar::api::model::Request::Containers;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// let response = client.request(Containers).await.expect("failed to request container list");
    /// println!("{:?}", response);
    /// # }
    /// ```
    pub async fn request(&mut self, request: Request) -> Result<Response, Error> {
        self.fused()?;

        let message = Message::Request { request };
        self.connection.send(message).await.map_err(|e| {
            self.fuse();
            Error::Io(e)
        })?;
        loop {
            match self.connection.next().await {
                Some(Ok(message)) => match message {
                    Message::Response { response } => break Ok(response),
                    Message::Notification { notification } => {
                        self.push_notification(notification)?
                    }
                    _ => unreachable!("invalid message {:?}", message),
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

    /// Request the identificaiton of this container
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use tokio::time::Duration;
    /// # use northstar::api::client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// let ident = client.ident().await.expect("failed to identity");
    /// println!("{}", ident);
    /// # }
    /// ```
    pub async fn ident(&mut self) -> Result<Container, Error> {
        match self.request(Request::Ident).await? {
            Response::Ident(container) => Ok(container),
            Response::Error(error) => Err(Error::Runtime(error)),
            _ => unreachable!("response on ident should be ident"),
        }
    }

    /// Request a list of installed containers
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use tokio::time::Duration;
    /// # use northstar::api::client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// let containers = client.containers().await.expect("failed to request container list");
    /// println!("{:#?}", containers);
    /// # }
    /// ```
    pub async fn containers(&mut self) -> Result<Vec<ContainerData>, Error> {
        match self.request(Request::Containers).await? {
            Response::Containers(containers) => Ok(containers),
            Response::Error(error) => Err(Error::Runtime(error)),
            _ => unreachable!("response on containers should be containers"),
        }
    }

    /// Request a list of repositories
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use tokio::time::Duration;
    /// # use northstar::api::client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// let repositories = client.repositories().await.expect("failed to request repository list");
    /// println!("{:#?}", repositories);
    /// # }
    /// ```
    pub async fn repositories(&mut self) -> Result<HashSet<RepositoryId>, Error> {
        match self.request(Request::Repositories).await? {
            Response::Repositories(repositories) => Ok(repositories),
            Response::Error(error) => Err(Error::Runtime(error)),
            _ => unreachable!("response on repositories should be ok or error"),
        }
    }

    /// Start container with name
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use std::time::Duration;
    /// # use northstar::api::client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// client.start("hello:0.0.1").await.expect("failed to start \"hello\"");
    /// // Print start notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn start(
        &mut self,
        container: impl TryInto<Container, Error = impl Into<Error>>,
    ) -> Result<(), Error> {
        self.start_with_args(container, empty::<&str>()).await
    }

    /// Start container name and pass args
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use std::time::Duration;
    /// # use northstar::api::client::Client;
    /// # use std::collections::HashMap;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// client.start_with_args("hello:0.0.1", ["--foo"]).await.expect("failed to start \"hello --foor\"");
    /// // Print start notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn start_with_args(
        &mut self,
        container: impl TryInto<Container, Error = impl Into<Error>>,
        args: impl IntoIterator<Item = impl TryInto<NonNulString, Error = impl Into<Error>>>,
    ) -> Result<(), Error> {
        self.start_with_args_env(container, args, empty::<(&str, &str)>())
            .await
    }

    /// Start container name and pass args and set additional env variables
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use std::time::Duration;
    /// # use northstar::api::client::Client;
    /// # use std::collections::HashMap;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// let mut env = HashMap::new();
    /// env.insert("FOO", "blah");
    /// client.start_with_args_env("hello:0.0.1", ["--dump", "-v"], env).await.expect("failed to start \"hello\"");
    /// // Print start notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn start_with_args_env(
        &mut self,
        container: impl TryInto<Container, Error = impl Into<Error>>,
        args: impl IntoIterator<Item = impl TryInto<NonNulString, Error = impl Into<Error>>>,
        env: impl IntoIterator<
            Item = (
                impl TryInto<NonNulString, Error = impl Into<Error>>,
                impl TryInto<NonNulString, Error = impl Into<Error>>,
            ),
        >,
    ) -> Result<(), Error> {
        let container = container.try_into().map_err(Into::into)?;

        let mut args_converted = vec![];
        for arg in args {
            args_converted.push(arg.try_into().map_err(Into::into)?);
        }

        let mut env_converted = HashMap::new();
        for (key, value) in env {
            let key = key.try_into().map_err(Into::into)?;
            let value = value.try_into().map_err(Into::into)?;
            env_converted.insert(key, value);
        }

        let args = args_converted;
        let env = env_converted;
        let request = Request::Start(container, args, env);

        match self.request(request).await? {
            Response::Ok => Ok(()),
            Response::Error(error) => Err(Error::Runtime(error)),
            _ => unreachable!("response on start should be ok or error"),
        }
    }

    /// Kill container with name
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use tokio::time::Duration;
    /// # use northstar::api::client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// client.kill("hello:0.0.1", 15).await.expect("failed to start \"hello\"");
    /// // Print stop notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn kill(
        &mut self,
        container: impl TryInto<Container, Error = impl Into<Error>>,
        signal: i32,
    ) -> Result<(), Error> {
        let container = container.try_into().map_err(Into::into)?;
        match self.request(Request::Kill(container, signal)).await? {
            Response::Ok => Ok(()),
            Response::Error(error) => Err(Error::Runtime(error)),
            _ => unreachable!("response on kill should be ok or error"),
        }
    }

    /// Install a npk
    ///
    /// ```no_run
    /// # use northstar::api::client::Client;
    /// # use std::time::Duration;
    /// # use std::path::Path;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// let npk = Path::new("test.npk");
    /// client.install(&npk, "default").await.expect("failed to install \"test.npk\" into repository \"default\"");
    /// # }
    /// ```
    pub async fn install(&mut self, npk: &Path, repository: &str) -> Result<Container, Error> {
        self.fused()?;
        let file = fs::File::open(npk).await.map_err(Error::Io)?;
        let size = file.metadata().await.unwrap().len();
        let request = Request::Install(repository.into(), size);
        let message = Message::Request { request };
        self.connection.send(message).await.map_err(|_| {
            self.fuse();
            Error::Stopped
        })?;

        self.connection.flush().await?;
        debug_assert!(self.connection.write_buffer().is_empty());

        let mut reader = io::BufReader::with_capacity(BUFFER_SIZE, file);
        let mut writer = BufWriter::with_capacity(BUFFER_SIZE, self.connection.get_mut());
        io::copy_buf(&mut reader, &mut writer).await.map_err(|e| {
            self.fuse();
            Error::Io(e)
        })?;

        loop {
            match self.connection.next().await {
                Some(Ok(message)) => match message {
                    Message::Response { response } => match response {
                        Response::Install(container) => break Ok(container),
                        Response::Error(error) => break Err(Error::Runtime(error)),
                        _ => unreachable!("response on install should be container or error"),
                    },
                    Message::Notification { notification } => {
                        self.push_notification(notification)?
                    }
                    _ => unreachable!("invalid response"),
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
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// client.uninstall("hello:0.0.1").await.expect("failed to uninstall \"hello\"");
    /// // Print stop notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn uninstall(
        &mut self,
        container: impl TryInto<Container, Error = impl Into<Error>>,
    ) -> Result<(), Error> {
        let container = container.try_into().map_err(Into::into)?;
        match self.request(Request::Uninstall(container)).await? {
            Response::Ok => Ok(()),
            Response::Error(error) => Err(Error::Runtime(error)),
            _ => unreachable!("response on uninstall should be ok or error"),
        }
    }

    /// Stop the runtime
    pub async fn shutdown(&mut self) {
        self.request(Request::Shutdown).await.ok();
    }

    /// Mount a container
    /// ```no_run
    /// # use northstar::api::client::Client;
    /// # use std::time::Duration;
    /// # use std::convert::TryInto;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// client.mount("test:0.0.1").await.expect("failed to mount");
    /// # }
    /// ```
    pub async fn mount<E, C>(&mut self, container: C) -> Result<MountResult, Error>
    where
        E: Into<Error>,
        C: TryInto<Container, Error = E>,
    {
        self.mount_all([container])
            .await
            .map(|mut r| r.pop().expect("invalid mount result"))
    }

    /// Mount a list of containers
    /// ```no_run
    /// # use northstar::api::client::Client;
    /// # use std::time::Duration;
    /// # use northstar::common::version::Version;
    /// # use std::path::Path;
    /// # use std::convert::TryInto;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// client.mount_all(vec!("hello-world:0.0.1", "cpueater:0.0.1")).await.expect("failed to mount");
    /// # }
    /// ```
    pub async fn mount_all<E, C, I>(&mut self, containers: I) -> Result<Vec<MountResult>, Error>
    where
        E: Into<Error>,
        C: TryInto<Container, Error = E>,
        I: 'a + IntoIterator<Item = C>,
    {
        self.fused()?;
        let mut result = vec![];
        for container in containers.into_iter() {
            let container = container.try_into().map_err(Into::into)?;
            result.push(container);
        }

        match self.request(Request::Mount(result)).await? {
            Response::Mount(result) => Ok(result),
            Response::Error(error) => Err(Error::Runtime(error)),
            _ => unreachable!("response on umount_all should be mount"),
        }
    }

    /// Umount a mounted container
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use northstar::api::client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// # let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// client.umount("hello:0.0.1").await.expect("failed to unmount \"hello:0.0.1\"");
    /// # }
    /// ```
    pub async fn umount<E, C>(&mut self, container: C) -> Result<UmountResult, Error>
    where
        E: Into<Error>,
        C: TryInto<Container, Error = E>,
    {
        self.umount_all([container])
            .await
            .map(|mut r| r.pop().expect("invalid mount result"))
    }

    /// Umount a list of mounted containers
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use northstar::api::client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// # let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// client.umount_all(vec!("hello:0.0.1", "cpueater:0.0.1")).await.expect("failed to unmount \"hello:0.0.1\" and \"cpueater:0.0.1\"");
    /// # }
    /// ```
    pub async fn umount_all<E, C, I>(&mut self, containers: I) -> Result<Vec<UmountResult>, Error>
    where
        E: Into<Error>,
        C: TryInto<Container, Error = E>,
        I: 'a + IntoIterator<Item = C>,
    {
        self.fused()?;

        let containers = containers.into_iter();
        let mut result = Vec::with_capacity(containers.size_hint().0);
        for container in containers {
            let container = container.try_into().map_err(Into::into)?;
            result.push(container);
        }

        match self.request(Request::Umount(result)).await? {
            Response::Umount(result) => Ok(result),
            Response::Error(error) => Err(Error::Runtime(error)),
            _ => unreachable!("response on umount should be umount"),
        }
    }

    /// Gather container statistics
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use northstar::api::client::Client;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// println!("{:?}", client.container_stats("hello:0.0.1").await.unwrap());
    /// # }
    /// ```
    pub async fn container_stats(
        &mut self,
        container: impl TryInto<Container, Error = impl Into<Error>>,
    ) -> Result<ContainerStats, Error> {
        let container = container.try_into().map_err(Into::into)?;
        match self.request(Request::ContainerStats(container)).await? {
            Response::ContainerStats(_, stats) => Ok(stats),
            Response::Error(error) => Err(Error::Runtime(error)),
            _ => unreachable!("response on container_stats should be a container_stats"),
        }
    }

    /// Create a token
    ///
    /// The `target` parameter must be the container name of the container that
    /// will try to verify the token.
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use northstar::api::client::Client;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// println!("{:?}", client.create_token("target", "hello:0.0.1").await.unwrap());
    /// # }
    /// ```
    pub async fn create_token<R, S>(&mut self, target: R, shared: S) -> Result<Token, Error>
    where
        R: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        let target = target.as_ref().to_vec();
        let shared = shared.as_ref().to_vec();
        match self.request(Request::TokenCreate(target, shared)).await? {
            Response::Token(token) => Ok(token),
            Response::Error(error) => Err(Error::Runtime(error)),
            _ => unreachable!("response on token should be a token reponse created"),
        }
    }

    /// Verify a slice of bytes with a token
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use northstar::api::client::Client;
    /// # use northstar::api::model::VerificationResult;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
    /// let token = client.create_token("hello:0.0.1", "target").await.unwrap();
    /// assert_eq!(client.verify_token(&token, "hello:0.0.1", "target").await.unwrap(), VerificationResult::Ok);
    /// assert_eq!(client.verify_token(&token, "#noafd", "target").await.unwrap(), VerificationResult::Ok);
    /// # }
    /// ```
    pub async fn verify_token<R, S>(
        &mut self,
        token: &Token,
        target: R,
        shared: S,
    ) -> Result<VerificationResult, Error>
    where
        R: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        let token = token.clone();
        let shared = shared.as_ref().to_vec();
        let target = target.as_ref().to_vec();
        match self
            .request(Request::TokenVerify(token, target, shared))
            .await?
        {
            Response::TokenVerification(result) => Ok(result),
            Response::Error(error) => Err(Error::Runtime(error)),
            _ => unreachable!("response on token verification should be a token verification"),
        }
    }

    /// Store a notification in the notification queue
    fn push_notification(&mut self, notification: Notification) -> Result<(), Error> {
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
///
/// # #[tokio::main(flavor = "current_thread")]
/// async fn main() {
///     let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None, Duration::from_secs(10)).await.unwrap();
///     client.start("hello:0.0.1").await.expect("failed to start \"hello\"");
///     while let Some(notification) = client.next().await {
///         println!("{:?}", notification);
///     }
/// }
/// ```
impl<T: AsyncRead + AsyncWrite + Unpin> Stream for Client<T> {
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
                        Message::Notification { notification } => {
                            Poll::Ready(Some(Ok(notification)))
                        }
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
