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
    api::{InstallationResult, MessageId, Notification},
    runtime::{error::Error, Event, EventTx},
};
use api::{
    Container, Message, Payload, Process, Request, Response, ShutdownResult, StartResult,
    StopResult,
};
use byteorder::{BigEndian, ByteOrder};
use log::{debug, error, info, warn};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};
use sync::mpsc;
use tempfile::tempdir;
use tokio::{
    fs::{self, OpenOptions},
    io::{self, AsyncRead, AsyncWrite, BufReader, BufWriter},
    net::{TcpListener, TcpStream},
    prelude::*,
    select,
    stream::StreamExt,
    sync::{self, mpsc::Sender},
    task,
};

/// A console is responsible for monitoring and serving incoming client connections
/// It feeds relevant events back to the runtime and forwards responses and notifications
/// to connected clients
pub struct Console {
    event_tx: EventTx,
    address: String,
}

enum ConsoleEvent {
    ApiMessage(MessageWithData),
    Disconnected,
}

struct MessageWithData {
    message: Message,
    path: Option<PathBuf>,
}

impl Console {
    pub fn new(address: &str, tx: &EventTx) -> Self {
        Self {
            event_tx: tx.clone(),
            address: address.to_owned(),
        }
    }

    /// process a remote API request
    /// if the request was valid, it is executed and the result is
    /// sent back to the sender
    pub async fn process(
        &self,
        state: &mut State,
        message: &Message,
        response_tx: mpsc::Sender<Message>,
    ) {
        let payload = &message.payload;
        if let Payload::Request(ref request) = payload {
            let response = match request {
                Request::Containers => {
                    debug!("Request::Containers received");
                    Response::Containers(list_containers(&state))
                }
                Request::Start(name) => match state.start(&name).await {
                    Ok(_) => Response::Start {
                        result: StartResult::Success,
                    },
                    Err(e) => {
                        error!("Failed to start {}: {}", name, e);
                        Response::Start {
                            result: StartResult::Error(e.to_string()),
                        }
                    }
                },
                Request::Stop(name) => {
                    match state.stop(&name, std::time::Duration::from_secs(1)).await {
                        Ok(_) => Response::Stop {
                            result: StopResult::Success,
                        },
                        Err(e) => {
                            error!("Failed to stop {}: {}", name, e);
                            Response::Stop {
                                result: StopResult::Error(e.to_string()),
                            }
                        }
                    }
                }
                Request::Uninstall { name, version } => {
                    match state.uninstall(name, version).await {
                        Ok(_) => Response::Uninstall {
                            result: api::UninstallResult::Success,
                        },
                        Err(e) => {
                            error!("Failed to uninstall {}: {}", name, e);
                            Response::Uninstall {
                                result: api::UninstallResult::Error(e.to_string()),
                            }
                        }
                    }
                }
                Request::Shutdown => match state.shutdown().await {
                    Ok(_) => Response::Shutdown {
                        result: ShutdownResult::Success,
                    },
                    Err(e) => Response::Shutdown {
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

    /// Open a TCP socket and listen for incoming connections
    /// spawn a task for each connection
    pub async fn start_listening(&self) -> Result<(), Error> {
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
                let event_tx_clone = event_tx.clone();
                if let Ok(stream) = stream {
                    task::spawn(async move {
                        if let Err(e) = connection(stream, event_tx_clone).await {
                            warn!("Error servicing connection: {}", e);
                        }
                    });
                }
            }
        });
        Ok(())
    }

    pub async fn installation_finished(
        &self,
        install_result: InstallationResult,
        msg_id: MessageId,
        response_message_tx: mpsc::Sender<Message>,
        registry_path: Option<PathBuf>,
        npk: &Path,
    ) {
        debug!("Installation finished, registry_path: {:?}", registry_path,);
        let mut install_result = install_result;
        if let (InstallationResult::Success, Some(new_path)) = (&install_result, registry_path) {
            // move npk into container dir
            if let Err(e) = fs::rename(npk, new_path).await {
                install_result =
                    InstallationResult::FileIoProblem(format!("Could not replace npk: {}", e));
            }
        }
        let response_message = Message {
            id: msg_id,
            payload: Payload::Response(Response::Install {
                result: install_result,
            }),
        };
        response_message_tx
            .send(response_message)
            .await
            .expect("TODO");
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
    message_tx: &mpsc::Sender<Option<MessageWithData>>,
    tmp_installation_dir: &Path,
) -> Result<(), Error> {
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
            context: "Could not read network package".to_string(),
            error: e,
        })?;

    let message: Message = serde_json::from_slice(&buffer)
        .map_err(|_| Error::Protocol("Could not parse protocol message".to_string()))?;
    let msg_with_data = match &message.payload {
        Payload::Installation(size) => {
            debug!("Incoming installation ({} bytes)", size);
            let tmp_installation_file_path = tmp_installation_dir.join(&format!(
                "tmp_install_file_{}.npk",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| format!("{}", d.as_millis()))
                    .unwrap_or_else(|_| "".to_string())
            ));
            let tmpfile = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&tmp_installation_file_path)
                .await
                .map_err(|e| Error::Io {
                    context: format!(
                        "Failed to create file {}",
                        tmp_installation_file_path.display()
                    ),
                    error: e,
                })?;
            let mut writer = BufWriter::new(tmpfile);
            let received_bytes = io::copy(&mut reader.take(*size as u64), &mut writer)
                .await
                .map_err(|e| Error::Io {
                    context: format!("Could not receive {} bytes", size),
                    error: e,
                })?;
            debug!("Received {} bytes. Starting installation", received_bytes);
            MessageWithData {
                message,
                path: Some(tmp_installation_file_path),
            }
        }
        _ => MessageWithData {
            message,
            path: None,
        },
    };
    // If sending on the message_tx part fails indicates a closed
    // connection. Ingore the error and discard the result.
    message_tx.send(Some(msg_with_data)).await.ok();
    Ok(())
}

// callback that is invoked whenever we receive a message from a connected client
async fn on_request(
    m: MessageWithData,
    sender_to_client: Sender<Message>,
    event_tx: &mut EventTx,
) -> io::Result<()> {
    let (tx_reply, mut rx_reply) = mpsc::channel::<Message>(1);
    let event = match m {
        MessageWithData {
            message:
                Message {
                    id,
                    payload: Payload::Installation(_),
                },
            path: Some(p),
        } => Event::Install(id, PathBuf::from(&p), tx_reply.clone()),
        _ => Event::Console(m.message, tx_reply.clone()),
    };
    event_tx
        .send(event)
        .await
        .expect("Internal channel error on main");

    // Wait for reply of the main loop
    // TODO: Add a timeout to not make the connection wait forever
    let reply = rx_reply
        .recv()
        .await
        .ok_or_else(|| io::Error::new(ErrorKind::Other, "Channel error"))?;

    // TODO: what to do with this error? Is the connection closed? Is this ok?
    sender_to_client.send(reply).await.ok();
    Ok(())
}

async fn connection(stream: TcpStream, mut event_tx: EventTx) -> Result<(), Error> {
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
    let (notification_sender, mut notification_receiver) = mpsc::channel::<Notification>(10);
    event_tx
        .send(Event::NotificationSubscription {
            id: subscription_id.clone(),
            subscriber: Some(notification_sender),
        })
        .await
        .map_err(|_| Error::Internal("Channel"))?;

    // Channel for sending response messages back to client
    let (response_tx, mut response_rx) = mpsc::channel::<Message>(1);

    let (reader, mut writer) = stream.into_split();

    // RX
    let dir = tmpdir.path().to_owned();
    let (tx, rx) = mpsc::channel::<Option<MessageWithData>>(1);
    task::spawn(async move {
        let mut reader = BufReader::new(reader);
        loop {
            if let Err(e) = read(&mut reader, &tx, &dir).await {
                warn!("Error receiving from socket: {}", e);
                tx.send(None).await.ok(); // TODO
                break;
            }
        }
    });
    let mut client_events = rx.map(|m| match m {
        Some(msg) => ConsoleEvent::ApiMessage(msg),
        None => ConsoleEvent::Disconnected,
    });

    // TX
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
        loop {
            while let Some(msg_to_send) = response_rx.recv().await {
                if let Err(e) = send_reply(&msg_to_send, &mut writer).await {
                    // TODO: Is the connection closed if this happens?
                    warn!("Error sending back to client: {}", e);
                    break;
                }
            }
        }
    });

    loop {
        select! {
            notification = notification_receiver.next() => {
                if let Some(notification) = notification {
                    let reply = Message {
                        id: uuid::Uuid::new_v4().to_string(),
                        payload: Payload::Notification(notification),
                    };
                    // If there's a error on the response tx indicates
                    // that the connection is closed. Break.
                    if response_tx.send(reply).await.is_err() {
                        break;
                    }
                } else {
                    break;
                }
            }
            console_event = client_events.next() => {
                match console_event {
                    Some(ConsoleEvent::ApiMessage(m)) => {
                        if let Err(e) = on_request(m, response_tx.clone(), &mut event_tx).await {
                            match e.kind() {
                                ErrorKind::UnexpectedEof => info!("Client {:?} disconnected", peer),
                                _ => {
                                    warn!("Error on handle_request to {:?}: {:?}", peer, e);
                                    break;
                                }
                            }
                            break;
                        }
                    }
                    Some(ConsoleEvent::Disconnected) | None => {
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
