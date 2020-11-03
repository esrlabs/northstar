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
    sync::{self, Receiver, Sender},
    task,
};
use byteorder::{BigEndian, ByteOrder};
use futures::stream::{self, StreamExt};
use io::ErrorKind;
use log::{debug, error, info, warn};
use tempfile::tempdir;

enum ConsoleEvent {
    SystemEvent(Notification),
    ApiMessage(MessageWithData),
    Disconnected,
}

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
                // let notification_rx_clone = notification_rx.clone();
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

struct MessageWithData {
    message: Message,
    path: Option<std::path::PathBuf>,
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
            // buf_writer.flush().await?;
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

async fn on_request(
    m: MessageWithData,
    event_tx: &mut EventTx,
    client_tx: Sender<Message>,
    rx_reply: &mut Receiver<Message>,
    tx_reply: &mut Sender<Message>,
) -> io::Result<()> {
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

    client_tx.send(reply).await;
    Ok(())
}

async fn connection(stream: TcpStream, mut event_tx: EventTx) -> Result<(), Error> {
    let peer = stream.peer_addr().map_err(|e| Error::Io {
        context: "Failed to get peer from command connection".to_string(),
        error: e,
    })?;
    debug!("Client {:?} connected", peer);

    let (notify_sender, notify_receiver) = sync::channel::<Notification>(10);
    let subscription_id = uuid::Uuid::new_v4().to_string();
    let subscription_event = Event::NotificationSubscription {
        id: subscription_id.clone(),
        subscriber: Some(notify_sender),
    };
    event_tx.send(subscription_event).await;

    let (mut message_tx, mut message_rx) = sync::channel::<Message>(1);
    let (client_tx, client_rx) = sync::channel::<Message>(10);
    let (socket_tx, socket_rx) = sync::channel::<Option<MessageWithData>>(1);
    let tmp_installation_dir = tempdir().map_err(|e| Error::Io {
        context: "Error creating temp installation dir".to_string(),
        error: e,
    })?;

    let tmp_installation_dir = std::path::PathBuf::from(tmp_installation_dir.path());

    // RX
    let reader = stream.clone();
    let tx = socket_tx.clone();
    task::spawn(async move {
        let mut buf_reader: io::BufReader<&TcpStream> = io::BufReader::new(&reader);
        loop {
            if let Err(e) = read(&mut buf_reader, &tx, &tmp_installation_dir).await {
                warn!("IO error on client connection: {}", e);
                tx.send(None).await;
                break;
            }
        }
    });

    // TX
    let mut writer = stream;
    task::spawn(async move {
        loop {
            match client_rx.recv().await {
                Ok(msg_to_send) => {
                    async fn send<W: Unpin + Write>(
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
                        writer.write_all(reply.as_bytes()).await.map(drop)
                    }

                    // Break this loop upon connection errors
                    if let Err(e) = send(&msg_to_send, &mut writer).await {
                        warn!("IO error on client connection: {}", e);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let client_events = socket_rx.map(|m| match m {
        Some(msg) => ConsoleEvent::ApiMessage(msg),
        None => ConsoleEvent::Disconnected,
    });
    let runtime_events = notify_receiver.map(ConsoleEvent::SystemEvent);
    let mut events = stream::select(client_events, runtime_events);

    while let Some(event) = events.next().await {
        match event {
            ConsoleEvent::SystemEvent(notification) => {
                let reply = Message {
                    id: uuid::Uuid::new_v4().to_string(),
                    payload: Payload::Notification(notification),
                };
                client_tx.send(reply).await;
            }
            ConsoleEvent::ApiMessage(message) => {
                let r = on_request(
                    message,
                    &mut event_tx,
                    client_tx.clone(),
                    &mut message_rx,
                    &mut message_tx,
                )
                .await;

                match r {
                    Ok(_) => (),
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                        info!("Client {:?} disconnected", peer);
                        break;
                    }
                    Err(e) => {
                        warn!("Failed to handle request from {:?}: {:?}", peer, e);
                        break;
                    }
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
