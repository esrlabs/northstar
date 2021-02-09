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

use super::{Event, RepositoryId};
use crate::{
    api::{self},
    runtime::{state::State, EventTx},
};
use async_trait::async_trait;
use futures::{sink::SinkExt, StreamExt};
use log::{debug, error, info, warn};
use std::{collections::HashMap, path::PathBuf};
use thiserror::Error;
use tokio::{
    fs,
    io::{self},
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
    select,
    sync::{self, broadcast, oneshot},
    task, time,
};
use tokio_util::sync::CancellationToken;
use url::Url;

type NotificationRx = broadcast::Receiver<api::model::Notification>;

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
    notification_tx: broadcast::Sender<api::model::Notification>,
    token: CancellationToken,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("IO error: {0} ({1})")]
    Io(String, #[source] io::Error),
    #[error("Invalid console address {0}, use either tcp://... or unix:...")]
    InvalidConsoleAddress(String),
}

trait ClientStream: Unpin + io::AsyncRead + io::AsyncWrite + Send {
    fn client_addr(&self) -> io::Result<String>;
}

impl ClientStream for UnixStream {
    fn client_addr(&self) -> io::Result<String> {
        Ok(format!("{:?}", self.peer_addr()?))
    }
}

impl ClientStream for TcpStream {
    fn client_addr(&self) -> io::Result<String> {
        Ok(format!("{:?}", self.peer_addr()?))
    }
}

#[async_trait]
trait Listener: Send {
    async fn accept_connection(&self) -> io::Result<Box<dyn ClientStream>>;
}

#[async_trait]
impl Listener for UnixListener {
    async fn accept_connection(&self) -> io::Result<Box<dyn ClientStream>> {
        Ok(Box::new(self.accept().await?.0))
    }
}

#[async_trait]
impl Listener for TcpListener {
    async fn accept_connection(&self) -> io::Result<Box<dyn ClientStream>> {
        Ok(Box::new(self.accept().await?.0))
    }
}

/// Creates either a Unix or Tcp socket as source of connections
async fn create_listener(url: &Url) -> Result<Box<dyn Listener>, Error> {
    match url.scheme() {
        "tcp" => {
            let host = url.host().unwrap_or(url::Host::Domain("localhost"));
            let port = url.port().unwrap_or(4200);
            let address = format!("{}:{}", host, port);
            debug!("Starting console on {}", &address);
            Ok(Box::new(TcpListener::bind(&address).await.map_err(
                |e| Error::Io(format!("Failed to open listener on {}", &address), e),
            )?))
        }
        "unix" => {
            debug!("Starting console on {}", &url.path());
            let path = url.path();
            Ok(Box::new(UnixListener::bind(&path).map_err(|e| {
                Error::Io(format!("Failed to open listener on {}", &path), e)
            })?))
        }
        _ => return Err(Error::InvalidConsoleAddress(url.to_string())),
    }
}

/// Spawns a new task for each new client
async fn listen_for_connections(
    listener: Box<dyn Listener>,
    event_tx: EventTx,
    notification_tx: broadcast::Sender<api::model::Notification>,
    token: CancellationToken,
) {
    loop {
        select! {
            stream = listener.accept_connection() => {
                match stream {
                    Ok(stream) => {
                        let event_tx = event_tx.clone();
                        let notification_rx = notification_tx.subscribe();
                        // Spawn a task for each incoming connection.
                        task::spawn(async move {
                            if let Err(e) = Console::connection(stream, event_tx, notification_rx).await {
                                warn!("Error servicing connection: {}", e);
                            }
                        });

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
}

impl Console {
    /// Construct a new console instance
    pub fn new(address: &str, tx: &EventTx) -> Result<Self, Error> {
        let (notification_tx, _notification_rx) = sync::broadcast::channel(100);
        Ok(Self {
            event_tx: tx.clone(),
            url: Url::parse(address)
                .map_err(|_| Error::InvalidConsoleAddress(address.to_string()))?,
            notification_tx,
            token: CancellationToken::new(),
        })
    }

    /// Process console events
    pub async fn process(
        &self,
        state: &mut State,
        request: &Request,
        response_tx: oneshot::Sender<api::model::Message>,
    ) {
        match request {
            Request::Message(message) => {
                let payload = &message.payload;
                if let api::model::Payload::Request(ref request) = payload {
                    let response = match request {
                        api::model::Request::Containers => {
                            api::model::Response::Containers(list_containers(&state))
                        }
                        api::model::Request::Repositories => {
                            debug!("Request::Repositories received");
                            api::model::Response::Repositories(list_repositories(&state))
                        }
                        api::model::Request::Start(name) => match state.start(&name).await {
                            Ok(_) => api::model::Response::Ok(()),
                            Err(e) => {
                                error!("Failed to start {}: {}", name, e);
                                api::model::Response::Err(e.into())
                            }
                        },
                        api::model::Request::Stop(name) => {
                            match state.stop(&name, std::time::Duration::from_secs(1)).await {
                                Ok(_) => api::model::Response::Ok(()),
                                Err(e) => {
                                    error!("Failed to stop {}: {}", name, e);
                                    api::model::Response::Err(e.into())
                                }
                            }
                        }
                        api::model::Request::Uninstall(name, version) => {
                            match state.uninstall(name, version).await {
                                Ok(_) => api::model::Response::Ok(()),
                                Err(e) => {
                                    error!("Failed to uninstall {}: {}", name, e);
                                    api::model::Response::Err(e.into())
                                }
                            }
                        }
                        api::model::Request::Shutdown => {
                            state.initiate_shutdown().await;
                            api::model::Response::Ok(())
                        }
                        api::model::Request::Install(_, _) => unreachable!(),
                    };

                    let response_message = api::model::Message {
                        id: message.id.clone(),
                        payload: api::model::Payload::Response(response),
                    };

                    // A error on the response_tx means that the connection
                    // was closed in the meantime. Ignore it.
                    response_tx.send(response_message).ok();
                } else {
                    warn!("Received message is not a request");
                }
            }
            Request::Install(repository, path) => {
                let payload = match state.install(&repository, &path).await {
                    Ok(_) => api::model::Response::Ok(()),
                    Err(e) => api::model::Response::Err(e.into()),
                };

                let response = api::model::Message::new_response(payload);

                // A error on the response_tx means that the connection
                // was closed in the meantime. Ignore it.
                response_tx.send(response).ok();
            }
        }
    }

    /// Open a TCP socket and listen for incoming connections
    /// spawn a task for each connection
    pub(crate) async fn listen(&self) -> Result<(), Error> {
        let listener = create_listener(&self.url).await?;
        let event_tx = self.event_tx.clone();
        let notification_tx = self.notification_tx.clone();
        let token = self.token.clone();
        task::spawn(async move {
            listen_for_connections(listener, event_tx, notification_tx, token).await;
        });
        Ok(())
    }

    /// Send a notification to the notification broadcast
    pub async fn notification(&self, notification: api::model::Notification) {
        self.notification_tx.send(notification).ok();
    }

    async fn connection(
        stream: Box<dyn ClientStream>,
        event_tx: EventTx,
        mut notification_rx: NotificationRx,
    ) -> Result<(), Error> {
        let peer = stream
            .client_addr()
            .map_err(|e| Error::Io("Failed to get peer from command connection".to_string(), e))?;

        debug!("Client {:?} connected", peer);

        // Get a framed stream and sink interface.
        let mut stream = api::codec::framed(stream);

        loop {
            select! {
                notification = notification_rx.recv() => {
                    // Process notifications received via the notification
                    // broadcast channel
                    let notification = match notification {
                        Ok(notification) => notification,
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            warn!("Client connection lagged notifications. Closing");
                            break;
                        }
                    };

                    if let Err(e) = stream.send(api::model::Message::new_notification(notification)).await {
                        warn!("{}: Connection error: {}", peer, e);
                        break;
                    }
                }
                message = stream.next() => {
                    let message = if let Some(Ok(message)) = message {
                        message
                    } else {
                        info!("{}: Connection closed", peer);
                        break;
                    };

                    let mut keep_file = None;

                    let request = if let api::model::Payload::Request(api::model::Request::Install(repository, size)) = message.payload {
                        info!("{}: Received installation request with size {}", peer, bytesize::ByteSize::b(size));
                        info!("{}: Using repository \"{}\"", peer, repository);
                        // Get a tmpfile name
                        let tmpfile = match tempfile::NamedTempFile::new() {
                            Ok(f) => f,
                            Err(e) => {
                                warn!("Failed to create tempfile: {}" , e);
                                break;
                            }
                        };

                        // Create a tmpfile
                        let mut file = match fs::File::create(&tmpfile.path()).await {
                            Ok(f) => f,
                            Err(e) => {
                                warn!("Failed to open tempfile: {}" , e);
                                break;
                            }
                        };

                        // Receive size bytes and dump to the tempfile
                        let start = time::Instant::now();
                        match io::copy(&mut io::AsyncReadExt::take(&mut stream, size), &mut file).await {
                            Ok(n) => {
                                info!("{}: Received {} in {:?}", peer, bytesize::ByteSize::b(n), start.elapsed());
                            }
                            Err(e) => {
                                warn!("{}: Connection error: {}" , peer, e);
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
                    let reply = reply_rx
                        .await
                        .expect("Internal channel error on client reply");

                    keep_file.take();

                    // Report result to client
                    if let Err(e) = stream.send(reply).await {
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

fn list_containers(state: &State) -> Vec<api::model::Container> {
    let mut containers: Vec<api::model::Container> = state
        .applications()
        .map(|app| api::model::Container {
            manifest: app.manifest().clone(),
            repository: app.container().repository.clone(),
            process: app.process_context().map(|f| api::model::Process {
                pid: f.process().pid(),
                uptime: f.uptime().as_nanos() as u64,
                resources: api::model::Resources {
                    memory: {
                        {
                            let page_size = page_size::get();
                            let pid = f.process().pid();

                            procinfo::pid::statm(pid as i32)
                                .ok()
                                .map(|statm| api::model::Memory {
                                    size: (statm.size * page_size) as u64,
                                    resident: (statm.resident * page_size) as u64,
                                    shared: (statm.share * page_size) as u64,
                                    text: (statm.text * page_size) as u64,
                                    data: (statm.data * page_size) as u64,
                                })
                        }
                    },
                },
            }),
        })
        .collect();
    let mut resources = state
        .resources()
        .map(|container| api::model::Container {
            manifest: container.manifest.clone(),
            process: None,
            repository: container.repository.clone(),
        })
        .collect();
    containers.append(&mut resources);
    containers
}

fn list_repositories(state: &State) -> HashMap<RepositoryId, api::model::Repository> {
    state
        .repositories()
        .iter()
        .map(|(id, repository)| {
            (
                id.clone(),
                api::model::Repository::new(repository.dir.clone()),
            )
        })
        .collect()
}
