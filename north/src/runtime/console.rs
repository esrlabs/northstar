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
use async_std::{
    fs::OpenOptions,
    io::{self, BufWriter, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    prelude::*,
    sync::{self, Sender},
    task,
};
use byteorder::{BigEndian, ByteOrder};
use futures::stream::{self, StreamExt};
use io::ErrorKind;
use log::{debug, error, info, warn};
use tempfile::tempdir;

/// A console is responsible for monitoring and serving incoming client connections
/// It feeds relevant events back to the runtime and forwards responses and notifications
/// to connected clients
pub struct Console {
    event_tx: EventTx,
    address: String,
}

enum ConsoleEvent {
    SystemEvent(Notification),
    ApiMessage(MessageWithData),
    Disconnected,
}

struct MessageWithData {
    message: Message,
    path: Option<std::path::PathBuf>,
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
        response_tx: sync::Sender<Message>,
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
            response_tx.send(response_message).await;
        } else {
            warn!("Received message is not a request");
        }
    }

    /// Open a TCP socket and listen for incoming connections
    /// spawn a task for each connection
    pub async fn start_listening(&self) -> Result<(), Error> {
        debug!("Starting console on {}", self.address);
        let event_tx = self.event_tx.clone();
        let listener = TcpListener::bind(&self.address)
            .await
            .map_err(|e| Error::Io {
                context: format!("Failed to open listener on {}", self.address),
                error: e,
            })?;

        task::spawn(async move {
            let mut incoming = listener.incoming();

            // Spawn a task for each incoming connection.
            while let Some(stream) = incoming.next().await {
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
        response_message_tx: sync::Sender<Message>,
        registry_path: Option<std::path::PathBuf>,
        npk: &std::path::Path,
    ) {
        debug!("Installation finished, registry_path: {:?}", registry_path,);
        let mut install_result = install_result;
        if let (InstallationResult::Success, Some(new_path)) = (&install_result, registry_path) {
            // move npk into container dir
            if let Err(e) = async_std::fs::rename(npk, new_path).await {
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
        response_message_tx.send(response_message).await
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

async fn read<R: Read + Unpin>(
    reader: &mut R,
    message_tx: &sync::Sender<Option<MessageWithData>>,
    tmp_installation_dir: &std::path::Path,
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
            let buf_writer = BufWriter::new(tmpfile);
            let received_bytes = io::copy(reader.take(*size as u64), buf_writer)
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
    message_tx.send(Some(msg_with_data)).await;
    Ok(())
}

// callback that is invoked whenever we receive a message from a connected client
async fn on_request(
    m: MessageWithData,
    sender_to_client: Sender<Message>,
    event_tx: &mut EventTx,
) -> io::Result<()> {
    let (tx_reply, rx_reply) = sync::channel::<Message>(1);
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
    event_tx.send(event).await;

    // Wait for reply of main loop
    // TODO: timeout
    let reply = rx_reply
        .recv()
        .await
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    sender_to_client.send(reply).await;
    Ok(())
}

fn start_sending_to_client(writer: &TcpStream, client_rx: sync::Receiver<Message>) {
    // setup send functionality
    let mut writer = writer.clone();
    task::spawn(async move {
        async fn send_reply<W: Unpin + Write>(reply: &Message, writer: &mut W) -> io::Result<()> {
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
            while let Ok(msg_to_send) = client_rx.recv().await {
                if let Err(e) = send_reply(&msg_to_send, &mut writer).await {
                    warn!("Error sending back to client: {}", e);
                    break;
                }
            }
        }
    });
}

fn start_receiving_from_client(
    reader: &TcpStream,
    tmp_installation_dir: std::path::PathBuf,
) -> impl Stream<Item = ConsoleEvent> {
    let (tx, rx) = sync::channel::<Option<MessageWithData>>(1);
    let reader = reader.clone();
    let _ = task::spawn(async move {
        let mut buf_reader: io::BufReader<&TcpStream> = io::BufReader::new(&reader);
        loop {
            if let Err(e) = read(&mut buf_reader, &tx, &tmp_installation_dir).await {
                warn!("Error receiving from socket: {}", e);
                tx.send(None).await;
                break;
            }
        }
    });
    rx.map(|m| match m {
        Some(msg) => ConsoleEvent::ApiMessage(msg),
        None => ConsoleEvent::Disconnected,
    })
}

async fn connection(stream: TcpStream, mut event_tx: EventTx) -> Result<(), Error> {
    let peer = stream.peer_addr().map_err(|e| Error::Io {
        context: "Failed to get peer from command connection".to_string(),
        error: e,
    })?;
    debug!("Client {:?} connected", peer);

    // for each new client connection we create a new channel
    // the rx end is used to report notifications to the client
    // while the tx end is stored in the runtime to broadcast notifications
    let (notify_sender, notify_receiver) = sync::channel::<Notification>(10);
    let subscription_id = uuid::Uuid::new_v4().to_string();
    event_tx
        .send(Event::NotificationSubscription {
            id: subscription_id.clone(),
            subscriber: Some(notify_sender),
        })
        .await;

    let (reader, writer) = &mut (&stream, &stream);

    // channel for sending response messages back to client
    let response_channel = sync::channel::<Message>(10);

    let tmp_installation_dir = tempdir().map_err(|e| Error::Io {
        context: "Error creating temp installation dir".to_string(),
        error: e,
    })?;

    let client_events = start_receiving_from_client(
        reader,
        std::path::PathBuf::from(tmp_installation_dir.path()),
    );

    // make sure everything sent through the response_channel is forwarded to the client
    start_sending_to_client(writer, response_channel.1);

    let runtime_events = notify_receiver.map(ConsoleEvent::SystemEvent);

    let mut events = stream::select(client_events, runtime_events);

    while let Some(event) = events.next().await {
        match event {
            ConsoleEvent::SystemEvent(notification) => {
                let reply = Message {
                    id: uuid::Uuid::new_v4().to_string(),
                    payload: Payload::Notification(notification),
                };
                response_channel.0.send(reply).await;
            }
            ConsoleEvent::ApiMessage(m) => {
                if let Err(e) = on_request(m, response_channel.0.clone(), &mut event_tx).await {
                    match e.kind() {
                        ErrorKind::UnexpectedEof => info!("Client {:?} disconnected", peer),
                        _ => warn!("Error on handle_request to {:?}: {:?}", peer, e),
                    }
                    break;
                }
            }
            ConsoleEvent::Disconnected => {
                debug!("Client disconnected");
                break;
            }
        }
    }

    debug!("Connection to {} closed", peer);

    event_tx
        .send(Event::NotificationSubscription {
            subscriber: None,
            id: subscription_id,
        })
        .await;

    Ok(())
}
