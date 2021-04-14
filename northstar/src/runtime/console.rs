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
use futures::{
    future::join_all,
    sink::SinkExt,
    stream::{self, FuturesUnordered},
    StreamExt,
};
use log::{debug, error, info, trace, warn};
use std::{path::PathBuf, unreachable};
use thiserror::Error;
use tokio::{
    fs,
    io::{self, AsyncRead, AsyncWrite},
    net::{TcpListener, UnixListener},
    select,
    sync::{self, broadcast, oneshot},
    task::{self},
    time,
};
use tokio_util::{either::Either, sync::CancellationToken};
use url::Url;

// Request from the main loop to the console
#[derive(Debug)]
pub(crate) enum Request {
    Message(model::Message),
    Install(RepositoryId, PathBuf),
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
    pub(crate) async fn listen(&mut self) -> Result<(), Error> {
        let event_tx = self.event_tx.clone();
        let notification_tx = self.notification_tx.clone();
        // Stop token for self *and* the connections
        let stop = self.stop.clone();

        match self.url.scheme() {
            "tcp" => {
                let addresses = self
                    .url
                    .socket_addrs(|| Some(4200))
                    .map_err(|e| Error::Io("Invalid console address".into(), e))?;
                let address = addresses
                    .first()
                    .ok_or_else(|| {
                        Error::Io(
                            "Invalid console url".into(),
                            io::Error::new(io::ErrorKind::Other, ""),
                        )
                    })?
                    .to_owned();

                debug!("Starting console on {}", &address);

                let listener = TcpListener::bind(&address).await.map_err(|e| {
                    Error::Io(format!("Failed to open tcp listener on {}", &address), e)
                })?;

                debug!("Started console on {}", &address);

                let task = task::spawn(async move {
                    // Connection tasks
                    let mut connections = FuturesUnordered::new();
                    loop {
                        select! {
                            stream = listener.accept() => {
                                match stream {
                                    Ok(stream) => {
                                        connections.push(task::spawn(Self::connection(
                                            stream.0,
                                            stream.1.to_string(),
                                            stop.clone(),
                                            event_tx.clone(),
                                            notification_tx.subscribe(),
                                        )));
                                    }
                                    Err(e) => {
                                        warn!("Error listening: {}", e);
                                        break;
                                    }
                                }
                            }
                            _ = connections.next(), if !connections.is_empty() => {},
                            _ = stop.cancelled() => {
                                drop(listener);
                                debug!("Closed listener on {}", address);
                                if ! connections.is_empty() {
                                    debug!("Waiting for connections to be closed");
                                    while connections.next().await.is_some() {}
                                }
                                break;
                            }
                        }
                    }
                });
                self.tasks.push(task);
            }
            "unix" => {
                let address = PathBuf::from(self.url.path());

                debug!("Starting console on {}", address.display());

                if address.exists() {
                    fs::remove_file(&address)
                        .await
                        .map_err(|e| Error::Io("Failed to remove unix socket".into(), e))?;
                }

                let listener = UnixListener::bind(&address).map_err(|e| {
                    Error::Io(
                        format!("Failed to open unix listener on {}", address.display()),
                        e,
                    )
                })?;

                debug!("Started console on {}", address.display());

                let task = task::spawn(async move {
                    // Connection tasks
                    let mut connections = FuturesUnordered::new();
                    loop {
                        select! {
                            stream = listener.accept() => {
                                match stream {
                                    Ok(stream) => {
                                        connections.push(task::spawn(Self::connection(
                                            stream.0,
                                            format!("{:?}", &stream.1),
                                            stop.clone(),
                                            event_tx.clone(),
                                            notification_tx.subscribe(),
                                        )));
                                    }
                                    Err(e) => {
                                        warn!("Error listening: {}", e);
                                        break;
                                    }
                                }
                            }
                            _ = connections.next(), if !connections.is_empty() => {},
                            _ = stop.cancelled() => {
                                drop(listener);
                                debug!("Closed listener on {}", address.display());
                                if address.exists() {
                                    fs::remove_file(&address)
                                        .await.expect("Failed to remove unix socket");
                                }
                                if ! connections.is_empty() {
                                    debug!("Waiting for connections to be closed");
                                    while connections.next().await.is_some() {}
                                }
                                break;
                            }
                        }
                    }
                });
                self.tasks.push(task);
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    /// Stop the listeners and wait for their shutdown
    pub async fn shutdown(self) -> Result<(), Error> {
        self.stop.cancel();
        join_all(self.tasks).await;
        Ok(())
    }

    /// Send a notification to the notification broadcast
    pub async fn notification(&self, notification: Notification) {
        self.notification_tx.send(notification).ok();
    }

    async fn connection<T: AsyncRead + AsyncWrite + Unpin>(
        stream: T,
        peer: String,
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
        let (protocol_version, notifications, connect_message_id) = match connect.await {
            Ok(Some(Ok(m))) => match m.payload {
                model::Payload::Connect(model::Connect::Connect {
                    version,
                    subscribe_notifications,
                }) => (version, subscribe_notifications, m.id),
                _ => {
                    warn!("{}: Received {:?} instead of Connect", peer, m.payload);
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
            let message = model::Message {
                id: connect_message_id,
                payload: model::Payload::Connect(connack),
            };
            network_stream.send(message).await.ok();
            return Ok(());
        } else {
            // Send ConnectAck
            let conack = model::Connect::ConnectAck;
            let message = model::Message {
                id: connect_message_id,
                payload: model::Payload::Connect(conack),
            };

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
        tokio::pin!(notifications);

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
                    let message_id = message.id.clone();

                    trace!("{}: --> {:?}", peer, message);

                    let mut keep_file = None;

                    let request =
                        if let api::model::Payload::Request(
                            api::model::Request::Install(repository, size)) =
                            message.payload
                        {
                            debug!(
                                "{}: Received installation request with size {}",
                                peer,
                                bytesize::ByteSize::b(size)
                            );
                            info!("{}: Using repository \"{}\"", peer, repository);
                            // Get a tmpfile name
                            let tmpfile = match tempfile::NamedTempFile::new() {
                                Ok(f) => f,
                                Err(e) => {
                                    warn!("Failed to create tempfile: {}", e);
                                    break;
                                }
                            };

                            // Create a tmpfile
                            let mut file = match fs::File::create(&tmpfile.path()).await {
                                Ok(f) => f,
                                Err(e) => {
                                    warn!("Failed to open tempfile: {}", e);
                                    break;
                                }
                            };

                            // Receive size bytes and dump to the tempfile
                            let start = time::Instant::now();
                            match io::copy(
                                &mut io::AsyncReadExt::take(&mut network_stream, size),
                                &mut file,
                            )
                            .await
                            {
                                Ok(n) => {
                                    debug!(
                                        "{}: Received {} in {:?}",
                                        peer,
                                        bytesize::ByteSize::b(n),
                                        start.elapsed()
                                    );
                                }
                                Err(e) => {
                                    warn!("{}: Connection error: {}", peer, e);
                                    break;
                                }
                            }

                            let tmpfile_path = tmpfile.path().to_owned();
                            keep_file = Some(tmpfile);
                            Request::Install(repository, tmpfile_path)
                        } else {
                            Request::Message(message)
                        };

                    // Create a oneshot channel for the runtimes reply
                    let (reply_tx, reply_rx) = oneshot::channel();

                    // Send the request to the runtime
                    event_tx
                        .send(Event::Console(request, reply_tx))
                        .await
                        .expect("Internal channel error on main");

                    // Wait for the reply from the runtime
                    select! {
                        // If the runtime shuts down the connection shall be closed and not wait for
                        // a reply
                        _ = stop.cancelled() => break,
                        Ok(response) = reply_rx => {
                            keep_file.take();

                            // Report result to client
                            let message = api::model::Message {
                                id: message_id,
                                payload: api::model::Payload::Response(response),
                            };

                            trace!("{}: <-- {:?}", peer, message);
                            if let Err(e) = network_stream.send(message).await {
                                warn!("{}: Connection error: {}", peer, e);
                                break;
                            }
                        }
                        else => break,
                    }
                }
            }
        }

        info!("{}: Connection closed", peer);

        Ok(())
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
            Notification::Exit { container, status } => model::Notification::Exit {
                container,
                status: status.into(),
            },
            Notification::Started(container) => model::Notification::Started(container),
            Notification::Stopped(container) => model::Notification::Stopped(container),
        }
    }
}
