use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::TryInto,
    env,
    iter::empty,
    os::unix::prelude::FromRawFd,
    path::Path,
    pin::Pin,
    task::Poll,
};

use error::Error;
use futures::{SinkExt, Stream, StreamExt};
use northstar_runtime::{
    api::{
        codec,
        model::{
            ConnectNack, Container, ContainerData, InspectResult, InstallResult, Message,
            MountResult, Notification, RepositoryId, Request, Response, Token, UmountResult,
            VerificationResult,
        },
    },
    common::non_nul_string::NonNulString,
};
use tokio::{
    fs,
    io::{self, AsyncRead, AsyncWrite, BufWriter},
};

/// Client errors
pub mod error;
pub use northstar_runtime::{
    api::{model, VERSION},
    common::name::Name,
};

/// Default buffer size for installation transfers
const BUFFER_SIZE: usize = 1024 * 1024;

/// Client for a Northstar runtime instance.
///
/// ```no_run
/// use futures::StreamExt;
/// use northstar_client::Client;
/// use northstar_client::model::Version;
///
/// # #[tokio::main(flavor = "current_thread")]
/// async fn main() {
///     let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
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
}

/// Northstar console connection
pub type Connection<T> = codec::Framed<T>;

/// Connect and return a raw stream and sink interface. See codec for details
///
/// # Arguments
///
/// * `io` - Medium for the connection (e.g. Unix or TCP socket)
/// * `subscribe_notifications` - Enables the reception of notifications through the connection.
///
/// # Errors
///
/// An error is returned in the following cases:
///
/// - A mismatch in the protocol version between both sides of the connection
/// - Unnecessary permissions
/// - OS errors
///
pub async fn connect<T: AsyncRead + AsyncWrite + Unpin>(
    io: T,
    subscribe_notifications: bool,
) -> Result<Connection<T>, Error> {
    let mut connection = codec::framed(io);

    // Send connect message
    connection
        .send(Message::Connect {
            connect: model::Connect {
                version: VERSION,
                subscribe_notifications,
            },
        })
        .await?;

    // Wait for conack
    let message = connection
        .next()
        .await
        .ok_or_else(|| Error::ConnectionClosed)??;

    match message {
        Message::ConnectAck { .. } => Ok(connection),
        Message::ConnectNack { connect_nack } => match connect_nack {
            ConnectNack::InvalidProtocolVersion { .. } => Err(Error::ProtocolVersion),
            ConnectNack::PermissionDenied => Err(Error::PermissionDenied),
        },
        _ => unreachable!("expecting connect ack or connect nack"),
    }
}

impl Client<tokio::net::UnixStream> {
    /// Tries to create a client by accessing `NORTHSTAR_CONSOLE` env variable
    ///
    /// # Errors
    ///
    /// An `Err` is returned if the `NORTHSTAR_CONSOLE` environment variable is not set or has an
    /// invalid file descriptor for the unix socket.
    ///
    pub async fn from_env(notifications: Option<usize>) -> Result<Self, Error> {
        let fd = env::var("NORTHSTAR_CONSOLE")
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "missing env variable"))?
            .parse::<i32>()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid env variable"))?;

        let std = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        std.set_nonblocking(true)?;

        let io = tokio::net::UnixStream::from_std(std)?;
        let client = Client::new(io, notifications).await?;
        Ok(client)
    }
}

impl<'a, T: AsyncRead + AsyncWrite + Unpin> Client<T> {
    /// Create a new northstar client and connect to a runtime instance running on `host`.
    ///
    /// # Arguments
    ///
    /// * `io` - Connection medium (e.g. Unix or TCP socket)
    /// * `notifications` - Optional buffer size for receiving notifications
    /// * `timeout` - Timeout of connection establishment
    ///
    /// # Errors
    ///
    /// In addition to the errors that can happen when trying to [`connect`], an `Err` is returned
    /// if the connection establishment times out.
    ///
    pub async fn new(io: T, notifications: Option<usize>) -> Result<Client<T>, Error> {
        let connection = connect(io, notifications.is_some()).await?;

        Ok(Client {
            connection,
            notifications: notifications.map(VecDeque::with_capacity),
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
    /// # use northstar_client::Client;
    /// # use northstar_client::model::Request::List;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// let response = client.request(List).await.expect("failed to request container list");
    /// println!("{:?}", response);
    /// # }
    /// ```
    pub async fn request(&mut self, request: Request) -> Result<Response, Error> {
        let message = Message::Request { request };
        self.connection.send(message).await?;
        loop {
            let message = self
                .connection
                .next()
                .await
                .ok_or_else(|| Error::ConnectionClosed)??;

            match message {
                Message::Response { response } => break Ok(response),
                Message::Notification { notification } => self.push_notification(notification)?,
                _ => unreachable!("invalid message {:?}", message),
            }
        }
    }

    /// Request the identificaiton of this container
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use northstar_client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// let ident = client.ident().await.expect("failed to identity");
    /// println!("{}", ident);
    /// # }
    /// ```
    pub async fn ident(&mut self) -> Result<Container, Error> {
        match self.request(Request::Ident).await? {
            Response::Ident(container) => Ok(container),
            Response::PermissionDenied(_) => Err(Error::PermissionDenied),
            _ => unreachable!("response on ident should be ident"),
        }
    }

    /// Request a list of installed containers
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use northstar_client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// let containers = client.list().await.expect("failed to request container list");
    /// println!("{:#?}", containers);
    /// # }
    /// ```
    pub async fn list(&mut self) -> Result<Vec<Container>, Error> {
        match self.request(Request::List).await? {
            Response::List(containers) => Ok(containers),
            Response::PermissionDenied(_) => Err(Error::PermissionDenied),
            _ => unreachable!("response on containers should be containers"),
        }
    }

    /// Request a list of repositories
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use northstar_client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// let repositories = client.repositories().await.expect("failed to request repository list");
    /// println!("{:#?}", repositories);
    /// # }
    /// ```
    pub async fn repositories(&mut self) -> Result<HashSet<RepositoryId>, Error> {
        match self.request(Request::Repositories).await? {
            Response::Repositories(repositories) => Ok(repositories),
            Response::PermissionDenied(_) => Err(Error::PermissionDenied),
            _ => unreachable!("response on repositories should be ok or error"),
        }
    }

    /// Start container with name
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use northstar_client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// client.start("hello:0.0.1").await.expect("failed to start \"hello\"");
    /// // Print start notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn start<C>(&mut self, container: C) -> Result<(), Error>
    where
        C: TryInto<Container>,
        C::Error: std::error::Error + Send + Sync + 'static,
    {
        self.start_with_args(container, empty::<&str>()).await
    }

    /// Start container name and pass args
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use northstar_client::Client;
    /// # use std::collections::HashMap;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// client.start_with_args("hello:0.0.1", ["--foo"]).await.expect("failed to start \"hello --foor\"");
    /// // Print start notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn start_with_args<C, A>(
        &mut self,
        container: C,
        args: impl IntoIterator<Item = A>,
    ) -> Result<(), Error>
    where
        C: TryInto<Container>,
        C::Error: std::error::Error + Send + Sync + 'static,
        A: TryInto<NonNulString>,
        A::Error: std::error::Error + Send + Sync + 'static,
    {
        self.start_with_args_env(container, args, empty()).await
    }

    /// Start container name and pass args and set additional env variables
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use northstar_client::Client;
    /// # use std::collections::HashMap;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// let mut env = HashMap::new();
    /// env.insert("FOO", "blah");
    /// client.start_with_args_env("hello:0.0.1", ["--dump", "-v"], env).await.expect("failed to start \"hello\"");
    /// // Print start notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn start_with_args_env<C, A>(
        &mut self,
        container: C,
        args: impl IntoIterator<Item = A>,
        env: impl IntoIterator<Item = (A, A)>,
    ) -> Result<(), Error>
    where
        C: TryInto<Container>,
        C::Error: std::error::Error + Send + Sync + 'static,
        A: TryInto<NonNulString>,
        A::Error: std::error::Error + Send + Sync + 'static,
    {
        let container = container
            .try_into()
            .map_err(|e| Error::InvalidArgument(e.to_string()))?;

        let mut args_converted = vec![];
        for arg in args {
            args_converted.push(
                arg.try_into()
                    .map_err(|e| Error::InvalidArgument(format!("invalid argument: {e}")))?,
            );
        }

        let mut env_converted = HashMap::new();
        for (key, value) in env {
            let key = key
                .try_into()
                .map_err(|e| Error::InvalidArgument(format!("invalid argument: {e}")))?;
            let value = value
                .try_into()
                .map_err(|e| Error::InvalidArgument(format!("invalid argument: {e}")))?;
            env_converted.insert(key, value);
        }

        let arguments = args_converted;
        let environment = env_converted;
        let request = Request::Start {
            container,
            arguments,
            environment,
        };

        match self.request(request).await? {
            Response::Start(model::StartResult::Ok { .. }) => Ok(()),
            Response::Start(model::StartResult::Error { error, .. }) => Err(Error::Runtime(error)),
            Response::PermissionDenied(_) => Err(Error::PermissionDenied),
            _ => unreachable!("response on start should be ok or error"),
        }
    }

    /// Kill container with name
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use northstar_client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// client.kill("hello:0.0.1", 15).await.expect("failed to start \"hello\"");
    /// // Print stop notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn kill<C>(&mut self, container: C, signal: i32) -> Result<(), Error>
    where
        C: TryInto<Container>,
        C::Error: std::error::Error + Send + Sync + 'static,
    {
        let container = container
            .try_into()
            .map_err(|e| Error::InvalidArgument(e.to_string()))?;
        match self.request(Request::Kill { container, signal }).await? {
            Response::Kill(model::KillResult::Ok { .. }) => Ok(()),
            Response::Kill(model::KillResult::Error { error, .. }) => Err(Error::Runtime(error)),
            Response::PermissionDenied(_) => Err(Error::PermissionDenied),
            _ => unreachable!("response on kill should be ok or error"),
        }
    }

    /// Install a npk from path
    ///
    /// ```no_run
    /// # use northstar_client::Client;
    /// # use std::path::Path;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// let npk = Path::new("test.npk");
    /// client.install_file(npk, "default").await.expect("failed to install \"test.npk\" into repository \"default\"");
    /// # }
    /// ```
    pub async fn install_file(&mut self, npk: &Path, repository: &str) -> Result<Container, Error> {
        let file = fs::File::open(npk).await?;
        let size = file.metadata().await?.len();

        self.install(file, size, repository).await
    }

    /// Install a npk
    ///
    /// ```no_run
    /// # use northstar_client::Client;
    /// # use std::path::Path;
    /// # use tokio::fs;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// let npk = fs::File::open("test.npk").await.expect("failed to open \"test.npk\"");
    /// let size = npk.metadata().await.unwrap().len();
    /// client.install(npk, size, "default").await.expect("failed to install \"test.npk\" into repository \"default\"");
    /// # }
    /// ```
    pub async fn install(
        &mut self,
        npk: impl AsyncRead + Unpin,
        size: u64,
        repository: &str,
    ) -> Result<Container, Error> {
        let request = Request::Install {
            repository: repository.into(),
            size,
        };
        let message = Message::Request { request };
        self.connection.send(message).await?;
        self.connection.flush().await?;
        debug_assert!(self.connection.write_buffer().is_empty());

        let mut reader = io::BufReader::with_capacity(BUFFER_SIZE, npk);
        let mut writer = BufWriter::with_capacity(BUFFER_SIZE, self.connection.get_mut());
        io::copy_buf(&mut reader, &mut writer).await?;

        loop {
            let message = self
                .connection
                .next()
                .await
                .ok_or_else(|| Error::ConnectionClosed)??;

            match message {
                Message::Response { response } => match response {
                    Response::Install(InstallResult::Ok { container }) => break Ok(container),
                    Response::Install(InstallResult::Error { error }) => {
                        break Err(Error::Runtime(error))
                    }
                    Response::PermissionDenied(_) => break Err(Error::PermissionDenied),
                    _ => unreachable!("response on install should be container or error"),
                },
                Message::Notification { notification } => self.push_notification(notification)?,
                _ => unreachable!("invalid response"),
            }
        }
    }

    /// Uninstall a npk and optionally wipe the containers persistent dir
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use northstar_client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// #   let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// client.uninstall("hello:0.0.1", false).await.expect("failed to uninstall \"hello\"");
    /// // Print stop notification
    /// println!("{:#?}", client.next().await);
    /// # }
    /// ```
    pub async fn uninstall<C>(&mut self, container: C, wipe: bool) -> Result<(), Error>
    where
        C: TryInto<Container>,
        C::Error: std::error::Error + Send + Sync + 'static,
    {
        let container = container
            .try_into()
            .map_err(|e| Error::InvalidArgument(format!("invalid container: {e}")))?;
        match self.request(Request::Uninstall { container, wipe }).await? {
            Response::Uninstall(model::UninstallResult::Ok { .. }) => Ok(()),
            Response::Uninstall(model::UninstallResult::Error { error, .. }) => {
                Err(Error::Runtime(error))
            }
            Response::PermissionDenied(_) => Err(Error::PermissionDenied),
            _ => unreachable!("response on uninstall should be ok or error"),
        }
    }

    /// Stop the runtime
    pub async fn shutdown(&mut self) {
        self.request(Request::Shutdown).await.ok();
    }

    /// Mount a container
    /// ```no_run
    /// # use northstar_client::Client;
    /// # use std::convert::TryInto;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// client.mount("test:0.0.1").await.expect("failed to mount");
    /// # }
    /// ```
    pub async fn mount<C>(&mut self, container: C) -> Result<MountResult, Error>
    where
        C: TryInto<Container>,
        C::Error: std::error::Error + Send + Sync + 'static,
    {
        self.mount_all([container])
            .await
            .map(|mut r| r.pop().expect("invalid mount result"))
    }

    /// Mount a list of containers
    /// ```no_run
    /// # use northstar_client::Client;
    /// # use northstar_client::model::Version;
    /// # use std::path::Path;
    /// # use std::convert::TryInto;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// client.mount_all(vec!("hello-world:0.0.1", "cpueater:0.0.1")).await.expect("failed to mount");
    /// # }
    /// ```
    pub async fn mount_all<C, I>(&mut self, containers: I) -> Result<Vec<MountResult>, Error>
    where
        C: TryInto<Container>,
        C::Error: std::error::Error + Send + Sync + 'static,
        I: 'a + IntoIterator<Item = C>,
    {
        let mut result = vec![];
        for container in containers.into_iter() {
            let container = container
                .try_into()
                .map_err(|e| Error::InvalidArgument(format!("invalid container: {e}")))?;
            result.push(container);
        }

        match self.request(Request::Mount { containers: result }).await? {
            Response::Mount(result) => Ok(result),
            Response::PermissionDenied(_) => Err(Error::PermissionDenied),
            _ => unreachable!("response on umount_all should be mount"),
        }
    }

    /// Umount a mounted container
    ///
    /// ```no_run
    /// # use northstar_client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// # let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// client.umount("hello:0.0.1").await.expect("failed to unmount \"hello:0.0.1\"");
    /// # }
    /// ```
    pub async fn umount<C>(&mut self, container: C) -> Result<UmountResult, Error>
    where
        C: TryInto<Container>,
        C::Error: std::error::Error + Send + Sync + 'static,
    {
        self.umount_all([container])
            .await
            .map(|mut r| r.pop().expect("invalid mount result"))
    }

    /// Umount a list of mounted containers
    ///
    /// ```no_run
    /// # use northstar_client::Client;
    /// #
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() {
    /// # let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// client.umount_all(vec!("hello:0.0.1", "cpueater:0.0.1")).await.expect("failed to unmount \"hello:0.0.1\" and \"cpueater:0.0.1\"");
    /// # }
    /// ```
    pub async fn umount_all<C, I>(&mut self, containers: I) -> Result<Vec<UmountResult>, Error>
    where
        C: TryInto<Container>,
        C::Error: std::error::Error + Send + Sync + 'static,
        I: 'a + IntoIterator<Item = C>,
    {
        let containers = containers.into_iter();
        let mut result = Vec::with_capacity(containers.size_hint().0);
        for container in containers {
            let container = container
                .try_into()
                .map_err(|e| Error::InvalidArgument(format!("invalid container: {e}")))?;
            result.push(container);
        }

        match self.request(Request::Umount { containers: result }).await? {
            Response::Umount(result) => Ok(result),
            Response::PermissionDenied(_) => Err(Error::PermissionDenied),
            _ => unreachable!("response on umount should be umount"),
        }
    }

    /// Gather container statistics
    ///
    /// ```no_run
    /// # use northstar_client::Client;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// println!("{:?}", client.inspect("hello:0.0.1").await.unwrap());
    /// # }
    /// ```
    pub async fn inspect<C>(&mut self, container: C) -> Result<ContainerData, Error>
    where
        C: TryInto<Container>,
        C::Error: std::error::Error + Send + Sync + 'static,
    {
        let container = container
            .try_into()
            .map_err(|e| Error::InvalidArgument(format!("invalid container: {e}")))?;
        match self.request(Request::Inspect { container }).await? {
            Response::Inspect(InspectResult::Ok { container: _, data }) => Ok(*data),
            Response::Inspect(InspectResult::Error {
                container: _,
                error,
            }) => Err(Error::Runtime(error)),
            Response::PermissionDenied(_) => Err(Error::PermissionDenied),
            _ => unreachable!("response on container_stats should be a container_stats"),
        }
    }

    /// Create a token
    ///
    /// The `target` parameter must be the container name (without version) of the container that
    /// will try to verify the token. The token can only be successfully verified by the container
    /// that is started with the name `target`!
    /// The `shared` parameter is added into the token in order to make it specific to a dedicated
    /// purpose, e.g. "mqtt".
    ///
    /// ```no_run
    /// # use northstar_client::Client;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// println!("{:?}", client.create_token("webserver", "http").await.unwrap());
    /// # }
    /// ```
    pub async fn create_token<R, S>(&mut self, target: R, shared: S) -> Result<Token, Error>
    where
        R: TryInto<Name>,
        R::Error: std::error::Error + Send + Sync + 'static,
        S: AsRef<[u8]>,
    {
        let target = target
            .try_into()
            .map_err(|e| Error::InvalidArgument(format!("invalid target container name: {e}")))?;
        let shared = shared.as_ref().to_vec();
        match self
            .request(Request::TokenCreate { target, shared })
            .await?
        {
            Response::Token(token) => Ok(token),
            Response::PermissionDenied(_) => Err(Error::PermissionDenied),
            _ => unreachable!("response on token should be a token reponse created"),
        }
    }

    /// Verify a slice of bytes with a token
    ///
    /// The `token` parameter shall contain a token that is received from a container.
    /// The `user` parameter must match the name of the container, that created the token
    /// and send it to the container that want to verify the token.
    /// `shared` is some salt that makes a token specific for a usecase can must just match
    /// the value used when the the token is created.
    ///
    /// ```no_run
    /// # use northstar_client::Client;
    /// # use northstar_client::model::VerificationResult;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
    /// let token = client.create_token("hello", "#noafd").await.unwrap(); // token can only verified by container `hello`
    /// assert_eq!(client.verify_token(&token, "hello", "#noafd").await.unwrap(), VerificationResult::Ok);
    /// assert_eq!(client.verify_token(&token, "hello", "").await.unwrap(), VerificationResult::Ok);
    /// # }
    /// ```
    pub async fn verify_token<R, S>(
        &mut self,
        token: &Token,
        user: R,
        shared: S,
    ) -> Result<VerificationResult, Error>
    where
        R: TryInto<Name>,
        R::Error: std::error::Error + Send + Sync + 'static,
        S: AsRef<[u8]>,
    {
        let token = token.clone();
        let shared = shared.as_ref().to_vec();
        let user = user
            .try_into()
            .map_err(|e| Error::InvalidArgument(format!("invalid user container name: {e}")))?;
        match self
            .request(Request::TokenVerify {
                token,
                user,
                shared,
            })
            .await?
        {
            Response::TokenVerification(result) => Ok(result),
            Response::PermissionDenied(_) => Err(Error::PermissionDenied),
            _ => unreachable!("response on token verification should be a token verification"),
        }
    }

    /// Store a notification in the notification queue
    fn push_notification(&mut self, notification: Notification) -> Result<(), Error> {
        if let Some(notifications) = &mut self.notifications {
            if notifications.len() == notifications.capacity() {
                Err(Error::LaggedNotifications)
            } else {
                notifications.push_back(notification);
                Ok(())
            }
        } else {
            Ok(())
        }
    }
}

/// Stream notifications
///
/// ```no_run
/// use futures::StreamExt;
/// # use northstar_client::Client;
///
/// # #[tokio::main(flavor = "current_thread")]
/// async fn main() {
///     let mut client = Client::new(tokio::net::TcpStream::connect("localhost:4200").await.unwrap(), None).await.unwrap();
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
