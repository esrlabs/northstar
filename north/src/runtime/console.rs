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

use super::state::State;
use crate::{
    api,
    api::{InstallationResult, Notification},
    runtime::{error::Error, Event, EventTx},
};
use api::{Container, Message, Payload, Process, ShutdownResult, StartResult, StopResult};
use byteorder::{BigEndian, ByteOrder};
use log::{debug, error, warn};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};
use sync::mpsc;
use tempfile::tempdir;
use tokio::{
    fs::OpenOptions,
    io::{self, AsyncRead, AsyncWrite, BufReader, BufWriter},
    net::{TcpListener, TcpStream},
    prelude::*,
    select,
    stream::StreamExt,
    sync::{self},
    task,
};

// Request from the main loop to the console
#[derive(Debug)]
pub enum Request {
    Message(Message),
    Install(Message, PathBuf),
}

/// A console is responsible for monitoring and serving incoming client connections
/// It feeds relevant events back to the runtime and forwards responses and notifications
/// to connected clients
pub struct Console {
    event_tx: EventTx,
    address: String,
}

impl Console {
    pub fn new(address: &str, tx: &EventTx) -> Self {
        Self {
            event_tx: tx.clone(),
            address: address.to_owned(),
        }
    }

    pub async fn process(
        &self,
        state: &mut State,
        request: &Request,
        response_tx: mpsc::Sender<Message>,
    ) {
        match request {
            Request::Message(message) => {
                let payload = &message.payload;
                if let Payload::Request(ref request) = payload {
                    let response = match request {
                        api::Request::Containers => {
                            debug!("Request::Containers received");
                            api::Response::Containers(list_containers(&state))
                        }
                        api::Request::Start(name) => match state.start(&name).await {
                            Ok(_) => api::Response::Start {
                                result: StartResult::Success,
                            },
                            Err(e) => {
                                error!("Failed to start {}: {}", name, e);
                                api::Response::Start {
                                    result: StartResult::Error(e.to_string()),
                                }
                            }
                        },
                        api::Request::Stop(name) => {
                            match state.stop(&name, std::time::Duration::from_secs(1)).await {
                                Ok(_) => api::Response::Stop {
                                    result: StopResult::Success,
                                },
                                Err(e) => {
                                    error!("Failed to stop {}: {}", name, e);
                                    api::Response::Stop {
                                        result: StopResult::Error(e.to_string()),
                                    }
                                }
                            }
                        }
                        api::Request::Uninstall { name, version } => {
                            match state.uninstall(name, version).await {
                                Ok(_) => api::Response::Uninstall {
                                    result: api::UninstallResult::Success,
                                },
                                Err(e) => {
                                    error!("Failed to uninstall {}: {}", name, e);
                                    api::Response::Uninstall {
                                        result: api::UninstallResult::Error(e.to_string()),
                                    }
                                }
                            }
                        }
                        api::Request::Shutdown => match state.shutdown().await {
                            Ok(_) => api::Response::Shutdown {
                                result: ShutdownResult::Success,
                            },
                            Err(e) => api::Response::Shutdown {
                                result: ShutdownResult::Error(e.to_string()),
                            },
                        },
                    };

                    let response_message = Message {
                        id: message.id.clone(),
                        payload: Payload::Response(response),
                    };

                    // A error on the response_tx means that the connection
                    // was closed in the meantime. Ignore it.
                    response_tx.send(response_message).await.ok();
                } else {
                    warn!("Received message is not a request");
                }
            }
            Request::Install(message, path) => {
                let payload = match state.install(&path).await {
                    Ok(_) => api::Response::Install {
                        result: InstallationResult::Success,
                    },
                    Err(e) => api::Response::Install { result: e.into() },
                };

                let message = Message {
                    id: message.id.clone(),
                    payload: Payload::Response(payload),
                };
                // A error on the response_tx means that the connection
                // was closed in the meantime. Ignore it.
                response_tx.send(message).await.ok();
            }
        }
    }

    /// Open a TCP socket and listen for incoming connections
    /// spawn a task for each connection
    pub async fn listen(&self) -> Result<(), Error> {
        debug!("Starting console on {}", self.address);
        let event_tx = self.event_tx.clone();
        let mut listener = TcpListener::bind(&self.address)
            .await
            .map_err(|e| Error::Io {
                context: format!("Failed to open listener on {}", self.address),
                error: e,
            })?;

        task::spawn(async move {
            // Spawn a task for each incoming connection.
            while let Some(stream) = listener.next().await {
                if let Ok(stream) = stream {
                    let event_tx = event_tx.clone();
                    task::spawn(async move {
                        if let Err(e) = connection(stream, event_tx).await {
                            warn!("Error servicing connection: {}", e);
                        }
                    });
                }
            }
        });
        Ok(())
    }
}

fn list_containers(state: &State) -> Vec<Container> {
    let mut app_containers: Vec<Container> = state
        .applications()
        .map(|app| Container {
            manifest: app.manifest().clone(),
            process: app.process_context().map(|f| Process {
                pid: f.process().pid(),
                uptime: f.uptime().as_nanos() as u64,
                memory: {
                    #[cfg(not(any(target_os = "linux", target_os = "android")))]
                    {
                        None
                    }
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    {
                        const PAGE_SIZE: usize = 4096;
                        let pid = f.process().pid();
                        let statm = procinfo::pid::statm(pid as i32).expect("Failed get statm");
                        Some(api::Memory {
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
    let mut resource_containers: Vec<Container> = state
        .resources()
        .map(|app| Container {
            manifest: app.manifest().clone(),
            process: None,
        })
        .collect();
    app_containers.append(&mut resource_containers);
    app_containers
}

async fn read<R: AsyncRead + Unpin>(
    reader: &mut R,
    tmpdir: &Path,
) -> Result<ConnectionEvent, Error> {
    // Read frame length
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf).await.map_err(|e| Error::Io {
        context: "Could not read length of network package".to_string(),
        error: e,
    })?;
    let frame_len = BigEndian::read_u32(&buf) as usize;

    // Read payload
    let mut buffer = vec![0; frame_len];
    reader
        .read_exact(&mut buffer)
        .await
        .map_err(|e| Error::Io {
            context: "Failed to read connection".to_string(),
            error: e,
        })?;

    // Deserialize message
    let message: Message = serde_json::from_slice(&buffer)
        .map_err(|_| Error::Protocol("Failed to parse protocol message".to_string()))?;

    match &message.payload {
        Payload::Installation(size) => {
            debug!("Incoming installation ({} bytes)", size);

            // Open a tmpfile
            let file = tmpdir.join(uuid::Uuid::new_v4().to_string());
            let tmpfile = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file)
                .await
                .map_err(|e| Error::Io {
                    context: format!("Failed to create file in {}", tmpdir.display()),
                    error: e,
                })?;

            // Stream size bytes into tmpfile
            let mut writer = BufWriter::new(tmpfile);
            let n = io::copy(&mut reader.take(*size as u64), &mut writer)
                .await
                .map_err(|e| Error::Io {
                    context: format!("Failed to receive {} bytes", size),
                    error: e,
                })?;
            debug!("Received {} bytes. Starting installation", n);
            Ok(ConnectionEvent::Install(message, file))
        }
        _ => Ok(ConnectionEvent::Request(message)),
    }
}

enum ConnectionEvent {
    Request(Message),
    Install(Message, PathBuf),
}

async fn connection(stream: TcpStream, event_tx: EventTx) -> Result<(), Error> {
    let subscription_id = uuid::Uuid::new_v4().to_string();
    let peer = stream.peer_addr().map_err(|e| Error::Io {
        context: "Failed to get peer from command connection".to_string(),
        error: e,
    })?;
    debug!("Client {:?} connected", peer);

    let tmpdir = tempdir().map_err(|e| Error::Io {
        context: "Error creating temp installation dir".to_string(),
        error: e,
    })?;

    // For each new client connection we create a new channel
    // the rx end is used to report notifications to the client
    // while the tx end is stored in the runtime to broadcast notifications
    let (notification_sender, mut notifications) = mpsc::channel::<Notification>(10);
    event_tx
        .send(Event::NotificationSubscription {
            id: subscription_id.clone(),
            subscriber: Some(notification_sender),
        })
        .await
        .map_err(|_| Error::Internal("Channel"))?;

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
        let (tx, mut rx) = mpsc::channel::<Message>(1);
        task::spawn(async move {
            async fn send_reply<W: Unpin + AsyncWrite>(
                reply: &Message,
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
            while let Some(msg_to_send) = rx.recv().await {
                if let Err(e) = send_reply(&msg_to_send, &mut writer).await {
                    // TODO: Is the connection closed if this happens?
                    warn!("Error sending back to client: {}", e);
                    break;
                }
            }
        });
        tx
    };

    loop {
        select! {
            notification = notifications.next() => {
                if let Some(notification) = notification {
                    let reply = Message {
                        id: uuid::Uuid::new_v4().to_string(),
                        payload: Payload::Notification(notification),
                    };
                    // If there's a error on the response tx indicates
                    // that the connection is closed. Break.
                    if client_out.send(reply).await.is_err() {
                        break;
                    }
                } else {
                    break;
                }
            }
            client_in = client_in.next() => {
                match client_in {
                    Some(request) => {
                        let request = match request {
                            ConnectionEvent::Request(request) => Request::Message(request),
                            ConnectionEvent::Install(message, npk) => Request::Install(message, npk),
                        };
                        let (reply_tx, mut reply_rx) = mpsc::channel::<Message>(1);
                        let event = Event::Console(request, reply_tx);
                        event_tx
                            .send(event)
                            .await
                            .expect("Internal channel error on main");

                        // Wait for reply of the main loop
                        // TODO: Add a timeout to not make the connection wait forever
                        let reply = reply_rx
                            .recv()
                            .await
                            .expect("Internal channel error on client reply");

                        if client_out.send(reply).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        debug!("Client disconnected");
                        break;
                    }
                }
            }
        }
    }

    debug!("Connection to {} closed", peer);

    event_tx
        .send(Event::NotificationSubscription {
            subscriber: None,
            id: subscription_id,
        })
        .await
        .expect("Internal channel error on main");

    Ok(())
}
