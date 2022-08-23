use super::{ContainerEvent, Event, NotificationTx, RepositoryId};
use crate::{
    api::{self, codec::Framed, VERSION},
    common::container::Container,
    runtime::{token::Token, EventTx, ExitStatus},
};
use anyhow::{bail, Context, Result};
use api::model;
use async_stream::stream;
use bytes::{Buf, Bytes};
use futures::{
    future::join_all,
    stream::{self, FuturesUnordered},
    Future, StreamExt,
};
use listener::Listener;
use log::{debug, info, trace, warn};
use semver::Comparator;
use std::{cmp::min, fmt, path::Path, unreachable};
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite},
    pin, select,
    sync::{broadcast, mpsc, oneshot},
    task, time,
};
use tokio_util::{either::Either, io::ReaderStream, sync::CancellationToken};
use url::Url;

pub use crate::npk::manifest::console::{Configuration, Permission, Permissions};

mod listener;
mod throttle;

/// Default maximum requests per second
const DEFAULT_REQUESTS_PER_SECOND: usize = 1024;
/// Default maximum length per request
const DEFAULT_MAX_REQUEST_SIZE: usize = 1024 * 1024;
/// Default maximum NPK size
const DEFAULT_MAX_INSTALL_STREAM_SIZE: u64 = 256 * 1_000_000;
/// Default timeout between two npks stream chunks
const DEFAULT_NPK_STREAM_TIMEOUT: u64 = 5;

// Request from the main loop to the console
#[derive(Debug)]
pub(crate) enum Request {
    Request(model::Request),
    Install(RepositoryId, mpsc::Receiver<Bytes>),
}

/// A console is responsible for monitoring and serving incoming client connections
/// It feeds relevant events back to the runtime and forwards responses and notifications
/// to connected clients
pub(crate) struct Console {
    /// Tx handle to the main loop
    event_tx: EventTx,
    /// Broadcast channel passed to connections to forward notifications
    notification_tx: NotificationTx,
    /// Shutdown the console by canceling this token
    stop: CancellationToken,
    /// Listener tasks. Currently there's just one task but when the console
    /// is exposed to containers via unix sockets this list will grow
    tasks: Vec<task::JoinHandle<()>>,
}

impl Console {
    /// Construct a new console instance
    pub(super) fn new(event_tx: EventTx, notification_tx: NotificationTx) -> Console {
        Self {
            event_tx,
            notification_tx,
            stop: CancellationToken::new(),
            tasks: Vec::new(),
        }
    }

    /// Spawn a task that listens on `url` for new connections. Spawn a task for
    /// each client
    pub(super) async fn listen(
        &mut self,
        url: &Url,
        configuration: &Configuration,
        token_validity: time::Duration,
    ) -> Result<()> {
        let event_tx = self.event_tx.clone();
        let notification_tx = self.notification_tx.clone();
        let configuration = configuration.clone();
        // Stop token for self *and* the connections
        let stop = self.stop.clone();

        debug!(
            "Starting console on {} with permissions \"{}\"",
            url, configuration.permissions
        );
        let task = match Listener::new(url)
            .await
            .context("failed to start console listener")?
        {
            Listener::Tcp(listener) => task::spawn(async move {
                serve(
                    || listener.accept(),
                    event_tx,
                    notification_tx,
                    stop,
                    configuration,
                    token_validity,
                )
                .await
            }),
            Listener::Unix(listener) => task::spawn(async move {
                serve(
                    || listener.accept(),
                    event_tx,
                    notification_tx,
                    stop,
                    configuration,
                    token_validity,
                )
                .await
            }),
        };

        self.tasks.push(task);

        Ok(())
    }

    /// Stop the listeners and wait for their shutdown
    pub(super) async fn shutdown(self) -> Result<()> {
        self.stop.cancel();
        join_all(self.tasks).await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn connection<T: AsyncRead + AsyncWrite + Unpin>(
        stream: T,
        peer: Peer,
        stop: CancellationToken,
        container: Option<Container>,
        configuration: Configuration,
        token_validity: time::Duration,
        event_tx: EventTx,
        mut notification_rx: broadcast::Receiver<(Container, ContainerEvent)>,
        timeout: Option<time::Duration>,
    ) -> Result<()> {
        let permissions = &configuration.permissions;
        if let Some(container) = &container {
            debug!(
                "Container {} connected with permissions {}",
                container, permissions
            );
        } else {
            debug!("Client {} connected with permissions {}", peer, permissions);
        }

        // Get a framed stream and sink interface.
        let max_request_size = configuration
            .max_request_size
            .unwrap_or(DEFAULT_MAX_REQUEST_SIZE);
        let stream = api::codec::framed_with_max_length(stream, max_request_size);

        // Limit requests per second
        let max_requests_per_sec = configuration
            .max_requests_per_sec
            .unwrap_or(DEFAULT_REQUESTS_PER_SECOND);
        let mut stream =
            throttle::Throttle::new(stream, max_requests_per_sec, time::Duration::from_secs(1));

        // Wait for a connect message within timeout
        let connect = stream.next();
        // TODO: This can for sure be done nicer
        let timeout = timeout.unwrap_or_else(|| time::Duration::from_secs(u64::MAX));
        let connect = time::timeout(timeout, connect);
        let (protocol_version, notifications) = match connect.await {
            Ok(Some(Ok(m))) => match m {
                model::Message::Connect {
                    connect:
                        model::Connect {
                            version,
                            subscribe_notifications,
                        },
                } => (version, subscribe_notifications),
                _ => {
                    warn!("{}: Received {:?} instead of Connect", peer, m);
                    return Ok(());
                }
            },
            Ok(Some(Err(e))) => {
                warn!("{}: Connection error: {}", peer, e);
                return Ok(());
            }
            Ok(None) => {
                info!("{}: Connection closed before connect", peer);
                return Ok(());
            }
            Err(_) => {
                info!("{}: Connection timed out", peer);
                return Ok(());
            }
        };

        // Check protocol version from connect message against local model version
        let version_request = semver::VersionReq {
            comparators: vec![Comparator {
                op: semver::Op::GreaterEq,
                major: VERSION.major,
                minor: Some(VERSION.minor),
                patch: None,
                pre: semver::Prerelease::default(),
            }],
        };
        let protocol_version = &protocol_version;
        if !version_request.matches(&(protocol_version.into())) {
            warn!(
                "{}: Client connected with insufficent protocol version {}. Expected {}. Disconnecting...",
                peer, protocol_version, VERSION
            );
            // Send a ConnectNack and return -> closes the connection
            let connect_nack = model::ConnectNack::InvalidProtocolVersion { version: VERSION };
            let message = model::Message::ConnectNack { connect_nack };
            stream.send(message).await.ok();
            return Ok(());
        }

        // Check notification permission if the client want's to subscribe to
        // notifications
        if notifications && !permissions.contains(&Permission::Notifications) {
            warn!(
                "{}: Requested notifications without notification permission. Disconnecting...",
                peer
            );
            // Send a ConnectNack and return -> closes the connection
            let connect_nack = model::ConnectNack::PermissionDenied;
            let message = model::Message::ConnectNack { connect_nack };
            stream.send(message).await.ok();
            return Ok(());
        }

        // Looks good - send ConnectAck
        let connect_ack = model::ConnectAck {
            configuration: configuration.clone(),
        };
        let message = model::Message::ConnectAck { connect_ack };
        if let Err(e) = stream.send(message).await {
            warn!("{}: Connection error: {}", peer, e);
            return Ok(());
        }

        // Notification input: If the client subscribe create a stream from the broadcast
        // receiver and otherwise drop it
        let notifications = if notifications {
            debug!("Client {} subscribed to notifications", peer);
            let stream = stream! { loop { yield notification_rx.recv().await; } };
            Either::Left(stream)
        } else {
            drop(notification_rx);
            Either::Right(stream::pending())
        };
        pin!(notifications);

        loop {
            select! {
                _ = stop.cancelled() => {
                    info!("{}: Closing connection", peer);
                    break;
                }
                notification = notifications.next() => {
                    // Process notifications received via the notification
                    // broadcast channel
                    let notification = match notification {
                        Some(Ok((container, event))) => (container, event).into(),
                        Some(Err(broadcast::error::RecvError::Closed)) => break,
                        Some(Err(broadcast::error::RecvError::Lagged(_))) => {
                            warn!("Client connection lagged notifications. Closing");
                            break;
                        }
                        None => break,
                    };

                    if let Err(e) = stream
                        .send(api::model::Message::Notification {notification })
                        .await
                    {
                        warn!("{}: Connection error: {}", peer, e);
                        break;
                    }
                }
                item = stream.next() => {
                    match item {
                        Some(Ok(model::Message::Request { request })) => {
                            trace!("{}: --> {:?}", peer, request);
                            let response = match process_request(&peer, &mut stream, &stop, &configuration, &event_tx, token_validity, request).await {
                                Ok(response) => response,
                                Err(e) => {
                                    warn!("Failed to process request: {}", e);
                                    break;
                                }
                            };
                            trace!("{}: <-- {:?}", peer, response);

                            if let Err(e) = stream.send(response).await {
                                warn!("{}: Connection error: {}", peer, e);
                                break;
                            }
                        }
                        Some(Ok(message)) => {
                            warn!("{}: Unexpected message: {:?}. Disconnecting...", peer, message);
                            break;
                        }
                        Some(Err(e)) => {
                            warn!("{}: Connection error: {:?}. Disconnecting...", peer, e);
                            break;
                        }
                        None => break,
                    }
                }
            }
        }

        info!("{}: Connection closed", peer);

        Ok(())
    }
}

/// Process a request
///
/// # Errors
///
/// If the streamed NPK is not valid and parseable a `Error::Npk(..)` is returned.
/// If the event loop is closed due to shutdown, this function will return `Error::EventLoopClosed`.
///
async fn process_request<S>(
    peer: &Peer,
    stream: &mut Framed<S>,
    stop: &CancellationToken,
    configuration: &Configuration,
    event_loop: &EventTx,
    token_validity: time::Duration,
    request: model::Request,
) -> Result<model::Message>
where
    S: AsyncRead + Unpin,
{
    let required_permission = match &request {
        model::Request::Ident { .. } => Permission::Ident,
        model::Request::Inspect { .. } => Permission::Inspect,
        model::Request::Install { .. } => Permission::Install,
        model::Request::Kill { .. } => Permission::Kill,
        model::Request::List => Permission::List,
        model::Request::Mount { .. } => Permission::Mount,
        model::Request::Repositories => Permission::Repositories,
        model::Request::Shutdown => Permission::Shutdown,
        model::Request::Start { .. } => Permission::Start,
        model::Request::TokenCreate { .. } => Permission::Token,
        model::Request::TokenVerify { .. } => Permission::Token,
        model::Request::Umount { .. } => Permission::Umount,
        model::Request::Uninstall { .. } => Permission::Uninstall,
    };

    let permissions = &configuration.permissions;
    if !permissions.contains(&required_permission) {
        return Ok(model::Message::Response {
            response: model::Response::PermissionDenied(request),
        });
    }

    let (reply_tx, reply_rx) = oneshot::channel();
    match request {
        model::Request::Ident => {
            let ident = match peer {
                #[allow(clippy::unwrap_used)]
                Peer::Extern(_) => Container::try_from("extern:0.0.0").unwrap(),
                Peer::Container(container) => container.clone(),
            };
            let response = api::model::Response::Ident(ident);
            reply_tx.send(response).ok();
        }
        model::Request::Install {
            repository,
            mut size,
        } => {
            debug!(
                "{}: Received installation request with size {}",
                peer,
                bytesize::ByteSize::b(size)
            );

            // Check the installation request size
            let max_install_stream_size = configuration
                .max_npk_install_size
                .unwrap_or(DEFAULT_MAX_INSTALL_STREAM_SIZE);
            if size > max_install_stream_size {
                bail!("npk size too large");
            }

            info!("{}: Using repository \"{}\"", peer, repository);

            // Send a Receiver<Bytes> to the runtime and forward n bytes to this channel
            let (tx, rx) = mpsc::channel(10);
            let request = Request::Install(repository, rx);
            trace!("    {:?} -> event loop", request);
            let event = Event::Console(request, reply_tx);
            event_loop.send(event).await?;

            // The codec might have pulled bytes in the the read buffer of the connection.
            if !stream.read_buffer().is_empty() {
                let available = stream.read_buffer().len();
                // Limit the first read operation to `size` if there's more data available.
                // If `size` bytes are available, `size` is decremented to 0 and the following
                // while let loop breaks.
                let read_max = min(size as usize, available);
                let buffer = stream.read_buffer_mut().copy_to_bytes(read_max);
                size -= buffer.len() as u64;
                tx.send(buffer).await.ok();
            }

            // If the connections breaks: just break. If the receiver is dropped: just break.
            let mut take = ReaderStream::with_capacity(stream.get_mut().take(size), 1024 * 1024);
            let timeout = time::Duration::from_secs(
                configuration
                    .npk_stream_timeout
                    .unwrap_or(DEFAULT_NPK_STREAM_TIMEOUT),
            );
            while let Some(buf) = time::timeout(timeout, take.next())
                .await
                .context("npk stream timeout")?
            {
                let buf = buf.context("npk steam")?;
                // Ignore any sending error because the stream needs to be drained for `size` bytes.
                tx.send(buf).await.ok();
            }
        }
        model::Request::TokenCreate { target, shared } => {
            let user = match peer {
                Peer::Extern(_) => "extern",
                Peer::Container(container) => container.name().as_ref(),
            };
            info!(
                "Creating token for user \"{}\" and target \"{}\" with shared \"{}\"",
                user,
                target,
                hex::encode(&shared)
            );
            let token: Vec<u8> = Token::new(token_validity, user, target, shared).into();
            let token = api::model::Token::from(token);
            let response = api::model::Response::Token(token);
            reply_tx.send(response).ok();
        }
        model::Request::TokenVerify {
            token,
            user,
            shared,
        } => {
            // The target is the container name, this connection belongs to.
            let target = match peer {
                Peer::Extern(_) => "extern",
                Peer::Container(container) => container.name().as_ref(),
            };
            info!(
                "Verifiying token for user \"{}\" and target \"{}\" with shared \"{}\"",
                user,
                target,
                hex::encode(&shared)
            );
            // The token has a valid length - verified by serde::deserialize
            let token = Token::from((token_validity, token.as_ref().to_vec()));
            let result = token.verify(user, target, &shared).into();
            let response = api::model::Response::TokenVerification(result);
            reply_tx.send(response).ok();
        }
        request => {
            let message = Request::Request(request);
            trace!("    {:?} -> event loop", message);
            let event = Event::Console(message, reply_tx);
            event_loop.send(event).await?;
        }
    }

    (select! {
        reply = reply_rx => reply.context("failed to receive reply"),
        _ = stop.cancelled() => bail!("shutdown"), // There can be a shutdown while we're waiting for an reply
    })
    .map(|response| {
        trace!("    {:?} <- event loop", response);
        response
    })
    .map(|response| model::Message::Response { response })
}

/// Function to handle connections
///
/// Generic handling of connections. The first parameter is a function that when called awaits for
/// a new connection. The connections are represented as a pair of a stream and some client
/// identifier.
///
/// All the connections container stored the tasks corresponding to each active connection. As
/// these tasks terminate, they are removed from the connections container. Once a stop is issued,
/// the termination of the remaining connections will be awaited.
///
async fn serve<AcceptFun, AcceptFuture, Stream, Addr>(
    accept: AcceptFun,
    event_tx: EventTx,
    notification_tx: broadcast::Sender<(Container, ContainerEvent)>,
    stop: CancellationToken,
    configuration: Configuration,
    token_validity: time::Duration,
) where
    AcceptFun: Fn() -> AcceptFuture,
    AcceptFuture: Future<Output = Result<(Stream, Addr), io::Error>>,
    Stream: AsyncWrite + AsyncRead + Unpin + Send + 'static,
    Addr: Into<Peer>,
{
    let mut connections = FuturesUnordered::new();
    loop {
        select! {
            _ = connections.next(), if !connections.is_empty() => (), // removes closed connections
            // If event_tx is closed then the runtime is shutting down therefore no new connections
            // are accepted
            connection = accept(), if !event_tx.is_closed() && !stop.is_cancelled() => {
                match connection {
                    Ok((stream, client)) => {
                        connections.push(
                        task::spawn(Console::connection(
                            stream,
                            client.into(),
                            stop.clone(),
                            None,
                            configuration.clone(),
                            token_validity,
                            event_tx.clone(),
                            notification_tx.subscribe(),
                            Some(time::Duration::from_secs(10)),
                        )));
                    }
                    Err(e) => {
                        warn!("Error listening: {:?}", e);
                        break;
                    }
                }
            }
            _ = stop.cancelled() => {
                if !connections.is_empty() {
                    debug!("Waiting for open connections");
                    while connections.next().await.is_some() {};
                }
                break;
            }
        }
    }
    debug!("Closed listener");
}

pub enum Peer {
    Extern(Url),
    Container(Container),
}

impl From<std::net::SocketAddr> for Peer {
    fn from(socket: std::net::SocketAddr) -> Self {
        match socket.ip() {
            std::net::IpAddr::V4(ip) => Url::parse(&format!("tcp://{}:{}", ip, socket.port()))
                .map(Peer::Extern)
                .expect("internal error"),
            std::net::IpAddr::V6(ip) => Url::parse(&format!("tcp://[{}]:{}", ip, socket.port()))
                .map(Peer::Extern)
                .expect("internal error"),
        }
    }
}

impl From<tokio::net::unix::SocketAddr> for Peer {
    fn from(socket: tokio::net::unix::SocketAddr) -> Self {
        let path = socket
            .as_pathname()
            .unwrap_or_else(|| Path::new("unnamed"))
            .display();
        Url::parse(&format!("unix://{}", path))
            .map(Peer::Extern)
            .expect("invalid url")
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Peer::Extern(url) => write!(f, "Remote({})", url),
            Peer::Container(container) => write!(f, "Container({})", container),
        }
    }
}

impl From<ExitStatus> for model::ExitStatus {
    fn from(e: ExitStatus) -> Self {
        match e {
            ExitStatus::Exit(code) => api::model::ExitStatus::Exit { code },
            ExitStatus::Signalled(signal) => api::model::ExitStatus::Signalled {
                signal: signal as u32,
            },
        }
    }
}

impl From<(Container, ContainerEvent)> for model::Notification {
    fn from(p: (Container, ContainerEvent)) -> model::Notification {
        let container = p.0.clone();
        match p.1 {
            ContainerEvent::Started => api::model::Notification::Started(container),
            ContainerEvent::Exit(status) => {
                api::model::Notification::Exit(container, status.into())
            }
            ContainerEvent::Installed => api::model::Notification::Install(container),
            ContainerEvent::Uninstalled => api::model::Notification::Uninstall(container),
            ContainerEvent::CGroup(event) => match event {
                super::CGroupEvent::Memory(memory) => api::model::Notification::CGroup(
                    container,
                    api::model::CgroupNotification::Memory(api::model::MemoryNotification {
                        low: memory.low,
                        high: memory.high,
                        max: memory.max,
                        oom: memory.oom,
                        oom_kill: memory.oom_kill,
                    }),
                ),
            },
        }
    }
}
