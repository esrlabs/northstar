use super::{
    config::ConsoleConfiguration as Configuration, ContainerEvent, Event, NotificationTx,
    RepositoryId,
};
use crate::{
    api::{self, codec::Framed},
    common::container::Container,
    npk::manifest::{self, Permission},
    runtime::{EventTx, ExitStatus},
};
use api::model;
use async_stream::stream;
use bytes::Bytes;
use futures::{
    future::join_all,
    sink::SinkExt,
    stream::{self, FuturesUnordered},
    Future, StreamExt, TryFutureExt,
};
use log::{debug, error, info, trace, warn};
use std::{
    fmt,
    path::{Path, PathBuf},
    unreachable,
};
use thiserror::Error;
use tokio::{
    fs,
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite},
    net::{TcpListener, UnixListener},
    pin, select,
    sync::{broadcast, mpsc, oneshot},
    task::{self},
    time,
};
use tokio_util::{either::Either, io::ReaderStream, sync::CancellationToken};
use url::Url;

const BUFFER_SIZE: usize = 1024 * 1024;

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

#[derive(Error, Debug)]
pub enum Error {
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("IO error: {0} ({1})")]
    Io(String, #[source] io::Error),
    #[error("Shutting down")]
    Shutdown,
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
    ) -> Result<(), Error> {
        let event_tx = self.event_tx.clone();
        let notification_tx = self.notification_tx.clone();
        let configuration = configuration.clone();
        // Stop token for self *and* the connections
        let stop = self.stop.clone();

        debug!(
            "Starting console on {} with permissions \"{}\"",
            url, configuration
        );
        let task = match Listener::new(url)
            .await
            .map_err(|e| Error::Io("Failed start console listener".into(), e))?
        {
            Listener::Tcp(listener) => task::spawn(async move {
                serve(
                    || listener.accept(),
                    event_tx,
                    notification_tx,
                    stop,
                    configuration,
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
                )
                .await
            }),
        };

        self.tasks.push(task);

        Ok(())
    }

    /// Stop the listeners and wait for their shutdown
    pub(super) async fn shutdown(self) -> Result<(), Error> {
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
        configuration: manifest::Console,
        event_tx: EventTx,
        mut notification_rx: broadcast::Receiver<(Container, ContainerEvent)>,
        timeout: Option<time::Duration>,
    ) -> Result<(), Error> {
        if let Some(container) = &container {
            debug!(
                "Container {} connected with permissions {}",
                container, configuration
            );
        } else {
            debug!(
                "Client {} connected with permissions {}",
                peer, configuration
            );
        }

        // Get a framed stream and sink interface.
        let mut network_stream = api::codec::Framed::with_capacity(stream, BUFFER_SIZE);

        // Wait for a connect message within timeout
        let connect = network_stream.next();
        // TODO: This can for sure be done nicer
        let timeout = timeout.unwrap_or_else(|| time::Duration::from_secs(u64::MAX));
        let connect = time::timeout(timeout, connect);
        let (protocol_version, notifications) = match connect.await {
            Ok(Some(Ok(m))) => match m {
                model::Message::Connect {
                    connect:
                        model::Connect::Connect {
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
        if protocol_version != model::version() {
            warn!(
                "{}: Client connected with invalid protocol version {}. Expected {}. Disconnecting...",
                peer, protocol_version, model::version()
            );
            // Send a ConnectNack and return -> closes the connection
            let error = model::ConnectNack::InvalidProtocolVersion {
                version: model::version(),
            };
            let connect = model::Connect::Nack { error };
            let message = model::Message::Connect { connect };
            network_stream.send(message).await.ok();
            return Ok(());
        }

        // Check notification permissions if the client want's to subscribe to
        // notifications
        if notifications && !configuration.contains(&Permission::Notifications) {
            warn!(
                "{}: Requested notifications without notification permission. Disconnecting...",
                peer
            );
            // Send a ConnectNack and return -> closes the connection
            let error = model::ConnectNack::PermissionDenied;
            let connect = model::Connect::Nack { error };
            let message = model::Message::Connect { connect };
            network_stream.send(message).await.ok();
            return Ok(());
        }

        // Looks good - send ConnectAck
        let connect = model::Connect::Ack {
            configuration: configuration.clone(),
        };
        let message = model::Message::Connect { connect };
        if let Err(e) = network_stream.send(message).await {
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

                    if let Err(e) = network_stream
                        .send(api::model::Message::new_notification(notification))
                        .await
                    {
                        warn!("{}: Connection error: {}", peer, e);
                        break;
                    }
                }
                item = network_stream.next() => {
                    if let Some(Ok(model::Message::Request { request })) = item {
                        trace!("{}: --> {:?}", peer, request);
                        let response = match process_request(&peer, &mut network_stream, &stop, &configuration, &event_tx, request).await {
                            Ok(response) => response,
                            Err(e) => {
                                warn!("Failed to process request: {}", e);
                                break;
                            }
                        };
                        trace!("{}: <-- {:?}", peer, response);

                        if let Err(e) = network_stream.send(response).await {
                            warn!("{}: Connection error: {}", peer, e);
                            break;
                        }
                    } else {
                        warn!("{}: Unexpected message: {:?}. Disconnecting...", peer, item);
                        break;
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
    client_id: &Peer,
    stream: &mut Framed<S>,
    stop: &CancellationToken,
    configuration: &manifest::Console,
    event_loop: &EventTx,
    request: model::Request,
) -> Result<model::Message, Error>
where
    S: AsyncRead + Unpin,
{
    let required_permission = match &request {
        model::Request::Shutdown => Permission::Shutdown,
        model::Request::Containers => Permission::Containers,
        model::Request::Repositories => Permission::Repositories,
        model::Request::Start { .. } => Permission::Start,
        model::Request::Kill { .. } => Permission::Kill,
        model::Request::Install { .. } => Permission::Install,
        model::Request::Mount { .. } => Permission::Mount,
        model::Request::Umount { .. } => Permission::Umount,
        model::Request::Uninstall { .. } => Permission::Uninstall,
        model::Request::ContainerStats { .. } => Permission::ContainerStatistics,
    };

    if !configuration.contains(&required_permission) {
        return Ok(model::Message::Response {
            response: model::Response::Error {
                error: model::Error::PermissionDenied {
                    permissions: configuration.iter().cloned().collect(),
                    required: required_permission,
                },
            },
        });
    }

    let (reply_tx, reply_rx) = oneshot::channel();
    if let model::Request::Install {
        repository,
        mut size,
    } = request
    {
        debug!(
            "{}: Received installation request with size {}",
            client_id,
            bytesize::ByteSize::b(size)
        );

        info!("{}: Using repository \"{}\"", client_id, repository);

        // Send a Receiver<Bytes> to the runtime and forward n bytes to this channel
        let (tx, rx) = mpsc::channel(10);
        let request = Request::Install(repository, rx);
        trace!("    {:?} -> event loop", request);
        let event = Event::Console(request, reply_tx);
        event_loop.send(event).map_err(|_| Error::Shutdown).await?;

        // The codec might have pulled bytes in the the read buffer of the connection.
        if !stream.read_buffer().is_empty() {
            let read_buffer = stream.read_buffer_mut().split();

            // TODO: handle this case. The connected entity pushed the install file
            // and a subsequenc request. If the codec pullen in the *full* install blob
            // and some bytes from the following command the logic is screwed up.
            assert!(read_buffer.len() as u64 <= size);

            size -= read_buffer.len() as u64;
            tx.send(read_buffer.freeze()).await.ok();
        }

        // If the connections breaks: just break. If the receiver is dropped: just break.
        let mut take = ReaderStream::with_capacity(stream.get_mut().take(size), 1024 * 1024);
        while let Some(Ok(buf)) = take.next().await {
            if tx.send(buf).await.is_err() {
                break;
            }
        }
    } else {
        let message = Request::Request(request);
        trace!("    {:?} -> event loop", message);
        let event = Event::Console(message, reply_tx);
        event_loop.send(event).map_err(|_| Error::Shutdown).await?;
    }

    (select! {
        reply = reply_rx => reply.map_err(|_| Error::Shutdown),
        _ = stop.cancelled() => Err(Error::Shutdown), // There can be a shutdown while we're waiting for an reply
    })
    .map(|response| {
        trace!("    {:?} <- event loop", response);
        response
    })
    .map(|response| model::Message::Response { response })
}

/// Types of listeners for console connections
enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl Listener {
    async fn new(url: &Url) -> io::Result<Listener> {
        let listener = match url.scheme() {
            "tcp" => {
                let address = url.socket_addrs(|| Some(4200))?.first().unwrap().to_owned();
                let listener = TcpListener::bind(&address).await?;
                debug!("Started console on {}", &address);

                Listener::Tcp(listener)
            }
            "unix" => {
                let path = PathBuf::from(url.path());

                // TODO this file should not be deleted here
                if path.exists() {
                    fs::remove_file(&path).await?
                }

                let listener = UnixListener::bind(&path)?;

                debug!("Started console on {}", path.display());
                Listener::Unix(listener)
            }
            _ => unreachable!(),
        };
        Ok(listener)
    }
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
    Remote(Url),
    Container(Container),
}

impl From<std::net::SocketAddr> for Peer {
    fn from(socket: std::net::SocketAddr) -> Self {
        let mut url = Url::parse("tcp://").unwrap();
        url.set_ip_host(socket.ip()).unwrap();
        url.set_port(Some(socket.port())).unwrap();
        Peer::Remote(url)
    }
}

impl From<tokio::net::unix::SocketAddr> for Peer {
    fn from(socket: tokio::net::unix::SocketAddr) -> Self {
        let path = socket
            .as_pathname()
            .unwrap_or_else(|| Path::new("unnamed"))
            .display();
        let url = Url::parse(&format!("unix://{}", path)).unwrap();
        Peer::Remote(url)
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Peer::Remote(url) => write!(f, "Remote({})", url),
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
            ContainerEvent::Started => api::model::Notification::Started { container },
            ContainerEvent::Exit(status) => api::model::Notification::Exit {
                container,
                status: status.into(),
            },
            ContainerEvent::Installed => api::model::Notification::Install { container },
            ContainerEvent::Uninstalled => api::model::Notification::Uninstall { container },
            ContainerEvent::CGroup(event) => match event {
                super::CGroupEvent::Memory(memory) => api::model::Notification::CGroup {
                    container,
                    notification: api::model::CgroupNotification::Memory(
                        api::model::MemoryNotification {
                            low: memory.low,
                            high: memory.high,
                            max: memory.max,
                            oom: memory.oom,
                            oom_kill: memory.oom_kill,
                        },
                    ),
                },
            },
        }
    }
}
