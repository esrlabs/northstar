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
    api::{self},
    runtime::EventTx,
};
use futures::{sink::SinkExt, StreamExt};
use log::{debug, error, info, trace, warn};
use std::{path::PathBuf, unreachable};
use thiserror::Error;
use tokio::{
    fs,
    io::{self, AsyncRead, AsyncWrite},
    net::{TcpListener, UnixListener},
    select,
    sync::{self, broadcast, oneshot},
    task, time,
};
use tokio_util::sync::CancellationToken;
use url::Url;

// Request from the main loop to the console
#[derive(Debug)]
pub(crate) enum Request {
    Message(api::model::Message),
    Install(RepositoryId, PathBuf),
}

/// A console is responsible for monitoring and serving incoming client connections
/// It feeds relevant events back to the runtime and forwards responses and notifications
/// to connected clients
pub(crate) struct Console {
    event_tx: EventTx,
    url: Url,
    notification_tx: broadcast::Sender<Notification>,
    token: CancellationToken,
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
    pub fn new(url: Url, tx: &EventTx) -> Result<Self, Error> {
        let (notification_tx, _notification_rx) = sync::broadcast::channel(100);
        Ok(Self {
            event_tx: tx.clone(),
            url,
            notification_tx,
            token: CancellationToken::new(),
        })
    }

    /// Open a TCP socket and listen for incoming connections
    /// spawn a task for each connection
    pub(crate) async fn listen(&self) -> Result<(), Error> {
        let event_tx = self.event_tx.clone();
        let notification_tx = self.notification_tx.clone();
        let token = self.token.clone();

        match self.url.scheme() {
            "tcp" => {
                let addresses = self
                    .url
                    .socket_addrs(|| Some(4200))
                    .map_err(|e| Error::Io("Invalid console address".into(), e))?;
                let address = addresses.first().ok_or_else(|| {
                    Error::Io(
                        "Invalid console url".into(),
                        io::Error::new(io::ErrorKind::Other, ""),
                    )
                })?;

                debug!("Starting console on {}", &address);

                let listener = TcpListener::bind(&address).await.map_err(|e| {
                    Error::Io(format!("Failed to open tcp listener on {}", &address), e)
                })?;

                debug!("Started console on {}", &address);

                task::spawn(async move {
                    loop {
                        select! {
                            stream = listener.accept() => {
                                match stream {
                                    Ok(stream) => {
                                        task::spawn(Self::connection(
                                            stream.0,
                                            stream.1.to_string(),
                                            event_tx.clone(),
                                            notification_tx.subscribe(),
                                        ));
                                    }
                                    Err(e) => {
                                        warn!("Error listening: {}", e);
                                        break;
                                    }
                                }
                            }
                            _ = token.cancelled() => break,
                        }
                    }
                });
            }
            "unix" => {
                let address = self.url.path().to_string();
                debug!("Starting console on {}", &address);

                let listener = UnixListener::bind(&address).map_err(|e| {
                    Error::Io(format!("Failed to open unix listener on {}", &address), e)
                })?;

                debug!("Started console on {}", &address);

                task::spawn(async move {
                    loop {
                        select! {
                            stream = listener.accept() => {
                                match stream {
                                    Ok(stream) => {
                                        task::spawn(Self::connection(
                                            stream.0,
                                            format!("{:?}", &stream.1),
                                            event_tx.clone(),
                                            notification_tx.subscribe(),
                                        ));
                                    }
                                    Err(e) => {
                                        warn!("Error listening: {}", e);
                                        break;
                                    }
                                }
                            }
                            _ = token.cancelled() => {
                                debug!("Removing {}", address);
                                fs::remove_file(address).await.expect("Failed to remove unix socket");
                                break;
                            }
                        }
                    }
                });
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    /// Send a notification to the notification broadcast
    pub async fn notification(&self, notification: Notification) {
        self.notification_tx.send(notification).ok();
    }

    async fn connection<T: AsyncRead + AsyncWrite + Unpin>(
        stream: T,
        peer: String,
        event_tx: EventTx,
        mut notification_rx: broadcast::Receiver<Notification>,
    ) -> Result<(), Error> {
        debug!("Client {:?} connected", peer);

        // Get a framed stream and sink interface.
        let mut network_stream = api::codec::framed(stream);

        loop {
            select! {
                notification = notification_rx.recv() => {
                    // Process notifications received via the notification
                    // broadcast channel
                    let notification = match notification {
                        Ok(notification) => notification.into(),
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            warn!("Client connection lagged notifications. Closing");
                            break;
                        }
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
                        info!("{}: Connection closed", peer);
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
                    let response: api::model::Response = reply_rx
                        .await
                        .expect("Internal channel error on client reply");

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
            }
        }
        info!("Connection to {} closed", peer);

        Ok(())
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        self.token.cancel();
    }
}
