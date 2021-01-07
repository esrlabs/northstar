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

use crate::{
    api,
    runtime::{state::State, Event, EventTx},
};
use byteorder::{BigEndian, ByteOrder};
use log::{debug, error, warn};
use npk::archive::RepositoryId;
use std::{
    collections::HashMap,
    io::ErrorKind,
    path::{Path, PathBuf},
};
use sync::mpsc;
use tempfile::tempdir;
use thiserror::Error;
use tokio::{
    fs::OpenOptions,
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter},
    net::{TcpListener, TcpStream},
    select,
    sync::{self, broadcast, oneshot},
    task,
};

// Events from message received by clients in deserialized form
enum ConnectionEvent {
    Request(api::Message),
    Install(api::Message, RepositoryId, PathBuf),
}

type NotificationRx = broadcast::Receiver<api::Notification>;

// Request from the main loop to the console
#[derive(Debug)]
pub(crate) enum Request {
    Message(api::Message),
    Install(api::Message, RepositoryId, PathBuf),
}

/// A console is responsible for monitoring and serving incoming client connections
/// It feeds relevant events back to the runtime and forwards responses and notifications
/// to connected clients
pub(crate) struct Console {
    event_tx: EventTx,
    address: String,
    notification_tx: broadcast::Sender<api::Notification>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("IO error: {0}")]
    Io(String, #[source] io::Error),
}

impl Console {
    /// Construct a new console instance
    pub fn new(address: &str, tx: &EventTx) -> Self {
        let (notification_tx, _notification_rx) = sync::broadcast::channel(100);
        Self {
            event_tx: tx.clone(),
            address: address.to_owned(),
            notification_tx,
        }
    }

    /// Process console events
    pub async fn process(
        &self,
        state: &mut State,
        request: &Request,
        response_tx: oneshot::Sender<api::Message>,
    ) {
        match request {
            Request::Message(message) => {
                let payload = &message.payload;
                if let api::Payload::Request(ref request) = payload {
                    let response = match request {
                        api::Request::Containers => {
                            debug!("Request::Containers received");
                            api::Response::Containers(list_containers(&state))
                        }
                        api::Request::Repositories => {
                            debug!("Request::Repositories received");
                            api::Response::Repositories(list_repositories(&state))
                        }
                        api::Request::Start(name) => match state.start(&name).await {
                            Ok(_) => api::Response::Ok(()),
                            Err(e) => {
                                error!("Failed to start {}: {}", name, e);
                                api::Response::Err(e.into())
                            }
                        },
                        api::Request::Stop(name) => {
                            match state.stop(&name, std::time::Duration::from_secs(1)).await {
                                Ok(_) => api::Response::Ok(()),
                                Err(e) => {
                                    error!("Failed to stop {}: {}", name, e);
                                    api::Response::Err(e.into())
                                }
                            }
                        }
                        api::Request::Uninstall { name, version } => {
                            match state.uninstall(name, version).await {
                                Ok(_) => api::Response::Ok(()),
                                Err(e) => {
                                    error!("Failed to uninstall {}: {}", name, e);
                                    api::Response::Err(e.into())
                                }
                            }
                        }
                        api::Request::Shutdown => {
                            state.initiate_shutdown().await;
                            api::Response::Ok(())
                        }
                        api::Request::Install(_, _) => unreachable!(),
                    };

                    let response_message = api::Message {
                        id: message.id.clone(),
                        payload: api::Payload::Response(response),
                    };

                    // A error on the response_tx means that the connection
                    // was closed in the meantime. Ignore it.
                    response_tx.send(response_message).ok();
                } else {
                    warn!("Received message is not a request");
                }
            }
            Request::Install(message, repository, path) => {
                let payload = match state.install(&repository, &path).await {
                    Ok(_) => api::Response::Ok(()),
                    Err(e) => api::Response::Err(e.into()),
                };

                let message = api::Message {
                    id: message.id.clone(),
                    payload: api::Payload::Response(payload),
                };
                // A error on the response_tx means that the connection
                // was closed in the meantime. Ignore it.
                response_tx.send(message).ok();
            }
        }
    }

    /// Open a TCP socket and listen for incoming connections
    /// spawn a task for each connection
    pub(crate) async fn listen(&self) -> Result<(), Error> {
        debug!("Starting console on {}", self.address);
        let event_tx = self.event_tx.clone();
        let listener = TcpListener::bind(&self.address)
            .await
            .map_err(|e| Error::Io(format!("Failed to open listener on {}", self.address), e))?;

        let notification_tx = self.notification_tx.clone();
        task::spawn(async move {
            // Spawn a task for each incoming connection.
            while let Ok(stream) = listener.accept().await {
                let event_tx = event_tx.clone();
                let notification_rx = notification_tx.subscribe();
                task::spawn(async move {
                    if let Err(e) = Self::connection(stream.0, event_tx, notification_rx).await {
                        warn!("Error servicing connection: {}", e);
                    }
                });
            }
        });
        Ok(())
    }

    /// Send a notification to the notification broadcast
    pub async fn notification(&self, notification: api::Notification) {
        self.notification_tx.send(notification).ok();
    }

    async fn connection(
        stream: TcpStream,
        event_tx: EventTx,
        mut notification_rx: NotificationRx,
    ) -> Result<(), Error> {
        let peer = stream
            .peer_addr()
            .map_err(|e| Error::Io("Failed to get peer from command connection".to_string(), e))?;
        debug!("Client {:?} connected", peer);

        let tmpdir = tempdir()
            .map_err(|e| Error::Io("Error creating temp installation dir".to_string(), e))?;

        let dir = tmpdir.path().to_owned();

        let (reader, mut writer) = stream.into_split();

        // RX
        let mut client_in = {
            let (tx, rx) = mpsc::channel(10);
            task::spawn(async move {
                let mut reader = BufReader::new(reader);
                loop {
                    match read(&mut reader, &dir).await {
                        Ok(event) => {
                            if tx.send(event).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("Error receiving from socket: {}", e);
                            break;
                        }
                    }
                }
            });
            rx
        };

        // TX
        let client_out = {
            let (tx, mut rx_messages) = mpsc::channel::<api::Message>(1);
            task::spawn(async move {
                async fn send<W: Unpin + AsyncWrite>(
                    reply: &api::Message,
                    writer: &mut W,
                ) -> io::Result<()> {
                    // Serialize reply
                    let reply = serde_json::to_string_pretty(&reply)
                        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

                    // Send reply
                    let mut buffer = [0u8; 4];
                    BigEndian::write_u32(&mut buffer, reply.len() as u32);
                    writer.write_all(&buffer).await?;
                    writer.write_all(reply.as_bytes()).await?;
                    Ok(())
                }

                loop {
                    select! {
                        message = rx_messages.recv() => {
                            if let Some(message) = message {
                                if let Err(e) = send(&message, &mut writer).await {
                                    // TODO: Is the connection closed if this happens?
                                    warn!("Error sending back to client: {}", e);
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                        notification = notification_rx.recv() => {
                            let payload = match notification {
                                Ok(notification) => notification,
                                Err(broadcast::error::RecvError::Closed) => break,
                                Err(broadcast::error::RecvError::Lagged(_)) => {
                                    warn!("Client connection lagged notifications. Closing");
                                    break;
                                }
                            };

                            let message = api::Message {
                                id: uuid::Uuid::new_v4().to_string(),
                                payload: api::Payload::Notification(payload),
                            };
                            if send(&message, &mut writer).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            tx
        };

        while let Some(request) = client_in.recv().await {
            let request = match request {
                ConnectionEvent::Request(request) => Request::Message(request),
                ConnectionEvent::Install(message, repository, npk) => {
                    Request::Install(message, repository, npk)
                }
            };

            let tmp_npk = match &request {
                Request::Install(_, _, npk) => Some(npk.to_owned()),
                _ => None,
            };

            let (reply_tx, reply_rx) = oneshot::channel();
            let event = Event::Console(request, reply_tx);
            event_tx
                .send(event)
                .await
                .expect("Internal channel error on main");

            let reply = reply_rx
                .await
                .expect("Internal channel error on client reply");

            if let Some(file) = tmp_npk {
                tokio::fs::remove_file(&file)
                    .await
                    .map_err(|e| Error::Io(format!("Failed to remove {}", file.display()), e))?;
            }

            if client_out.send(reply).await.is_err() {
                break;
            }
        }

        debug!("Connection to {} closed", peer);

        Ok(())
    }
}

fn list_containers(state: &State) -> Vec<api::Container> {
    let mut containers: Vec<api::Container> = state
        .applications()
        .map(|app| api::Container {
            manifest: app.manifest().clone(),
            repository: app.container().repository.clone(),
            process: app.process_context().map(|f| api::Process {
                pid: f.process().pid(),
                uptime: f.uptime().as_nanos() as u64,
                memory: {
                    {
                        const PAGE_SIZE: usize = 4096;
                        let pid = f.process().pid();

                        procinfo::pid::statm(pid as i32)
                            .ok()
                            .map(|statm| api::Memory {
                                size: (statm.size * PAGE_SIZE) as u64,
                                resident: (statm.resident * PAGE_SIZE) as u64,
                                shared: (statm.share * PAGE_SIZE) as u64,
                                text: (statm.text * PAGE_SIZE) as u64,
                                data: (statm.data * PAGE_SIZE) as u64,
                            })
                    }
                },
            }),
        })
        .collect();
    let mut resources = state
        .resources()
        .map(|container| api::Container {
            manifest: container.manifest.clone(),
            process: None,
            repository: container.repository.clone(),
        })
        .collect();
    containers.append(&mut resources);
    containers
}

fn list_repositories(state: &State) -> HashMap<RepositoryId, api::Repository> {
    fn from(repository: &crate::runtime::state::Repository) -> api::Repository {
        api::Repository {
            dir: repository.dir.clone(),
        }
    }
    state
        .repositories()
        .iter()
        .map(|(id, repository)| (id.clone(), from(repository)))
        .collect()
}

async fn read<R: AsyncRead + Unpin>(
    reader: &mut R,
    tmpdir: &Path,
) -> Result<ConnectionEvent, Error> {
    // Read frame length
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf).await.map_err(|e| {
        Error::Io(
            "Failed to read frame length of network package".to_string(),
            e,
        )
    })?;
    let frame_len = BigEndian::read_u32(&buf) as usize;

    // Read payload
    let mut buffer = vec![0; frame_len];
    reader
        .read_exact(&mut buffer)
        .await
        .map_err(|e| Error::Io("Failed to read payload".to_string(), e))?;

    // Deserialize message
    let message: api::Message = serde_json::from_slice(&buffer)
        .map_err(|_| Error::Protocol("Failed to deserialize message".to_string()))?;

    match &message.payload {
        api::Payload::Request(api::Request::Install(repository, size)) => {
            debug!("Incoming installation ({} bytes)", size);

            // Open a tmpfile
            let file = tmpdir.join(uuid::Uuid::new_v4().to_string());
            let tmpfile = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file)
                .await
                .map_err(|e| {
                    Error::Io(format!("Failed to create file in {}", tmpdir.display()), e)
                })?;

            // Stream size bytes into tmpfile
            let mut writer = BufWriter::new(tmpfile);
            let n = io::copy(&mut reader.take(*size as u64), &mut writer)
                .await
                .map_err(|e| Error::Io(format!("Failed to receive {} bytes", size), e))?;
            debug!("Received {} bytes. Starting installation", n);
            Ok(ConnectionEvent::Install(
                message.clone(),
                repository.to_string(),
                file,
            ))
        }
        _ => Ok(ConnectionEvent::Request(message)),
    }
}
