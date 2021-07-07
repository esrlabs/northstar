// Copyright (c) 2019 - 2020 ESRLabs
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

use super::{Event, Notification, RepositoryId};
use crate::{
    api,
    runtime::{EventTx, ExitStatus},
};
use api::model;
use bytes::Bytes;
use futures::{
    future::join_all,
    sink::SinkExt,
    stream::{self, FuturesUnordered},
    Future, StreamExt, TryFutureExt,
};
use log::{debug, error, info, trace, warn};
use std::{fmt, path::PathBuf, unreachable};
use thiserror::Error;
use tokio::{
    fs,
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, BufReader},
    net::{TcpListener, UnixListener},
    pin, select,
    sync::{self, broadcast, mpsc, oneshot},
    task::{self},
    time,
};
use tokio_util::{either::Either, io::ReaderStream, sync::CancellationToken};
use url::Url;

// Request from the main loop to the console
#[derive(Debug)]
pub(crate) enum Request {
    Message(model::Message),
    Install(RepositoryId, mpsc::Receiver<Bytes>),
}

/// A console is responsible for monitoring and serving incoming client connections
/// It feeds relevant events back to the runtime and forwards responses and notifications
/// to connected clients
pub(crate) struct Console {
    /// Tx handle to the main loop
    event_tx: EventTx,
    /// Listening address/url
    url: Url,
    /// Broadcast channel passed to connections to forward notifications
    notification_tx: broadcast::Sender<Notification>,
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
    pub(super) fn new(url: &Url, event_tx: EventTx) -> Console {
        let (notification_tx, _notification_rx) = sync::broadcast::channel(100);

        Self {
            event_tx,
            url: url.clone(),
            notification_tx,
            stop: CancellationToken::new(),
            tasks: Vec::new(),
        }
    }

    /// Open a TCP socket and listen for incoming connections
    /// spawn a task for each connection
    pub(super) async fn listen(&mut self) -> Result<(), Error> {
        let event_tx = self.event_tx.clone();
        let notification_tx = self.notification_tx.clone();
        // Stop token for self *and* the connections
        let stop = self.stop.clone();

        let task = match Listener::new(&self.url)
            .await
            .map_err(|e| Error::Io("Failed start console listener".into(), e))?
        {
            Listener::Tcp(listener) => task::spawn(async move {
                handle_connections(|| listener.accept(), event_tx, notification_tx, stop).await
            }),
            Listener::Unix(listener) => task::spawn(async move {
                handle_connections(|| listener.accept(), event_tx, notification_tx, stop).await
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

    /// Send a notification to the notification broadcast
    pub(super) async fn notification(&self, notification: Notification) {
        self.notification_tx.send(notification).ok();
    }

    async fn connection<T: AsyncRead + AsyncWrite + Unpin>(
        stream: T,
        peer: ClientId,
        stop: CancellationToken,
        event_tx: EventTx,
        mut notification_rx: broadcast::Receiver<Notification>,
    ) -> Result<(), Error> {
        debug!("Client {} connected", peer);

        // Get a framed stream and sink interface.
        let mut network_stream = api::codec::framed(stream);

        // Wait for a connect message within timeout
        let connect = network_stream.next();
        let connect = time::timeout(time::Duration::from_secs(5), connect);
        let (protocol_version, notifications) = match connect.await {
            Ok(Some(Ok(m))) => match m {
                model::Message::Connect(model::Connect::Connect {
                    version,
                    subscribe_notifications,
                }) => (version, subscribe_notifications),
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
                "{}: Client connected with invalid protocol version {}",
                peer, protocol_version
            );
            // Send a ConnectNack and return -> closes the connection
            let connack = model::ConnectNack::InvalidProtocolVersion(model::version());
            let connack = model::Connect::ConnectNack(connack);
            let message = model::Message::Connect(connack);
            network_stream.send(message).await.ok();
            return Ok(());
        } else {
            // Send ConnectAck
            let conack = model::Connect::ConnectAck;
            let message = model::Message::Connect(conack);

            if let Err(e) = network_stream.send(message).await {
                warn!("{}: Connection error: {}", peer, e);
                return Ok(());
            }
        }

        // Notification input: If the client subscribe create a stream from the broadcast
        // receiver and otherwise drop it
        let notifications = if notifications {
            debug!("Client {} subscribed to notifications", peer);
            let stream = async_stream::stream! { loop { yield notification_rx.recv().await; } };
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
                        Some(Ok(notification)) => notification.into(),
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
                    let message = if let Some(Ok(msg)) = item {
                        msg
                    } else {
                        break;
                    };

                    trace!("{}: --> {:?}", peer, message);
                    let response = match process_request(&peer, &mut network_stream, &stop, &event_tx, message).await {
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
    client_id: &ClientId,
    stream: &mut S,
    stop: &CancellationToken,
    event_loop: &EventTx,
    message: model::Message,
) -> Result<model::Message, Error>
where
    S: AsyncRead + Unpin,
{
    let (reply_tx, reply_rx) = oneshot::channel();
    if let model::Message::Request(model::Request::Install(repository, size)) = message {
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

        // If the connections breaks: just break. If the receiver is dropped: just break.
        let mut take = ReaderStream::new(BufReader::new(stream.take(size)));
        while let Some(Ok(buf)) = take.next().await {
            if tx.send(buf).await.is_err() {
                break;
            }
        }
    } else {
        let request = Request::Message(message);
        trace!("    {:?} -> event loop", request);
        let event = Event::Console(request, reply_tx);
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
    .map(model::Message::Response)
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
                debug!("Starting console on {}", &address);
                let listener = TcpListener::bind(&address).await?;
                debug!("Started console on {}", &address);

                Listener::Tcp(listener)
            }
            "unix" => {
                let path = PathBuf::from(url.path());
                debug!("Starting console on {}", path.display());

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
async fn handle_connections<AcceptConnection, Connection, Stream, Client, E>(
    accept: AcceptConnection,
    event_tx: EventTx,
    notification_tx: broadcast::Sender<Notification>,
    stop: CancellationToken,
) where
    AcceptConnection: Fn() -> Connection,
    Connection: Future<Output = Result<(Stream, Client), E>>,
    Stream: AsyncWrite + AsyncRead + Unpin + Send + 'static,
    Client: Into<ClientId>,
    E: fmt::Debug,
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
                            event_tx.clone(),
                            notification_tx.subscribe(),
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

struct ClientId(String);

impl From<std::net::SocketAddr> for ClientId {
    fn from(socket: std::net::SocketAddr) -> Self {
        ClientId(socket.to_string())
    }
}

impl From<tokio::net::unix::SocketAddr> for ClientId {
    fn from(socket: tokio::net::unix::SocketAddr) -> Self {
        ClientId(format!("{:?}", socket))
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<ExitStatus> for model::ExitStatus {
    fn from(e: ExitStatus) -> Self {
        match e {
            ExitStatus::Exit(e) => model::ExitStatus::Exit(e),
            ExitStatus::Signaled(s) => model::ExitStatus::Signaled(s as u32),
        }
    }
}

impl From<Notification> for model::Notification {
    fn from(n: Notification) -> Self {
        match n {
            Notification::OutOfMemory(container) => model::Notification::OutOfMemory(container),
            Notification::Exit(container, status) => {
                model::Notification::Exit(container, status.into())
            }
            Notification::Install(container) => model::Notification::Install(container),
            Notification::Uninstall(container) => model::Notification::Uninstall(container),
            Notification::Started(container) => model::Notification::Started(container),
            Notification::Stopped(container, status) => {
                model::Notification::Stopped(container, status.into())
            }
        }
    }
}
