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
    api::{InstallationResult, MessageId},
    runtime::{Event, EventTx, NotificationRx, SystemNotification},
};
use anyhow::{Context, Result};
use api::{
    Container, Message, Payload, Process, Request, Response, ShutdownResult, StartResult,
    StopResult,
};
use async_std::{
    fs::OpenOptions,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    prelude::*,
    sync::{self, Receiver, Sender},
    task,
};
use byteorder::{BigEndian, ByteOrder};
use futures::stream::StreamExt;
use io::ErrorKind;
use log::{debug, error, info, warn};
use tempfile::tempdir;

#[derive(Default)]
pub struct Console;

impl Console {
    pub async fn new(
        address: &str,
        tx: &EventTx,
        notification_rx: NotificationRx,
    ) -> Result<Console> {
        Self::start(address, tx.clone(), notification_rx).await?;
        Ok(Console::default())
    }

    pub async fn process(
        &self,
        state: &mut State,
        message: &Message,
        response_tx: sync::Sender<Message>,
    ) -> Result<()> {
        let payload = &message.payload;
        if let Payload::Request(ref request) = payload {
            let response = match request {
                Request::Containers => {
                    debug!("Request::Containers received");
                    let containers = state
                        .applications()
                        .map(|app| {
                            Container {
                                manifest: app.manifest().clone(),
                                process: app.process_context().map(|f| Process {
                                    pid: f.process().pid(),
                                    uptime: f.uptime().as_nanos() as u64,
                                    memory: {
                                        #[cfg(not(any(
                                            target_os = "linux",
                                            target_os = "android"
                                        )))]
                                        {
                                            None
                                        }
                                        #[cfg(any(target_os = "linux", target_os = "android"))]
                                        {
                                            // TODO
                                            const PAGE_SIZE: usize = 4096;
                                            let pid = f.process().pid();
                                            let statm = procinfo::pid::statm(pid as i32)
                                                .expect("Failed get statm");
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
                            }
                        })
                        .collect();

                    Response::Containers(containers)
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
                    let _ = name;
                    let _ = version;
                    Response::Uninstall {
                        result: api::UninstallResult::Error("unimplemented".into()),
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
            Ok(())
        } else {
            // TODO
            panic!("Received message is not a request");
        }
    }

    /// Open a TCP socket and read lines terminated with `\n`.
    async fn start(address: &str, tx: EventTx, notification_rx: NotificationRx) -> Result<()> {
        debug!("Starting console on {}", address);

        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("Failed to open listener on {}", address))?;

        task::spawn(async move {
            let mut incoming = listener.incoming();

            // Spawn a task for each incoming connection.
            while let Some(stream) = incoming.next().await {
                if let Ok(stream) = stream {
                    task::spawn(connection_loop(stream, tx.clone(), notification_rx.clone()));
                }
            }
        });
        Ok(())
    }

    pub async fn installation_finished(
        &self,
        success: InstallationResult,
        msg_id: MessageId,
        response_message_tx: sync::Sender<Message>,
        registry_path: Option<std::path::PathBuf>,
        npk: &std::path::Path,
    ) {
        debug!(
            "Installation finished, registry_path: {:?}, npk path: {}",
            registry_path,
            npk.display()
        );
        let mut success = success;
        if let (InstallationResult::Success, Some(new_path)) = (&success, registry_path) {
            // move npk into container dir
            if let Err(e) = std::fs::rename(npk, new_path) {
                success = InstallationResult::InternalError(format!("Could not place npk: {}", e));
            }
        }
        let response_message = Message {
            id: msg_id,
            payload: Payload::Response(Response::Install { result: success }),
        };
        response_message_tx.send(response_message).await
    }
}

// struct NotificationCatcher {
//     notification_rx: NotificationReceiver,
// }

// impl futures::Stream for NotificationCatcher {
//     type Item = Option<SystemNotification>;
//     fn poll_next(
//         mut self: std::pin::Pin<&mut Self>,
//         _cx: &mut std::task::Context,
//     ) -> futures::task::Poll<Option<Self::Item>> {
//         self.notification_rx.receive()
//         let mut buffer = vec![0; 20];
//         let message: Message = serde_json::from_slice(&buffer).unwrap();
//         futures::task::Poll::Ready(Some(Some(Ok(message))))
//     }
// }

// struct MessageReceiver<R: Unpin + Read> {
//     reader: R,
// }

// impl<R: Unpin + Read> futures::Stream for MessageReceiver<R> {
//     type Item = Option<Result<Message>>;
//     fn poll_next(
//         mut self: std::pin::Pin<&mut Self>,
//         _cx: &mut std::task::Context,
//     ) -> futures::task::Poll<Option<Self::Item>> {
//         // // Read frame length
//         // let mut buf = [0u8; 4];
//         // self.reader.read_exact(&mut buf).await.unwrap();
//         // let frame_len = BigEndian::read_u32(&buf) as usize;

//         // // Read payload
//         // let mut buffer = vec![0; frame_len];
//         // self.reader.read_exact(&mut buffer).await.unwrap();

//         // let message: Message = serde_json::from_slice(&buffer).unwrap();
//         // futures::task::Poll::Ready(Some(Some(Ok(message))))
//         futures::task::Poll::Ready(Some(None))
//     }
// }

struct MessageWithData {
    message: Message,
    path: Option<std::path::PathBuf>,
}

async fn receive_message_from_socket<R: Read + Unpin>(
    buf_reader: &mut R,
    message_tx: &sync::Sender<MessageWithData>,
    tmp_installation_dir: &std::path::Path,
) -> Result<()> {
    // Read frame length
    let mut buf = [0u8; 4];
    buf_reader.read_exact(&mut buf).await?;
    let frame_len = BigEndian::read_u32(&buf) as usize;

    // Read payload
    let mut buffer = vec![0; frame_len];
    buf_reader.read_exact(&mut buffer).await?;

    let message: Message = serde_json::from_slice(&buffer)?;
    let msg_with_data = match &message.payload {
        Payload::Installation(size, name) => {
            let tmp_installation_file_path = tmp_installation_dir.join(&name);
            let mut tmpfile = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&tmp_installation_file_path)
                .await?;
            let mut received_bytes = 0usize;
            while received_bytes < *size {
                let received = buf_reader.read(&mut buffer).await?;
                if received > 0 {
                    tmpfile.write_all(&buffer[..received]).await?;
                    received_bytes += received;
                }
            }
            tmpfile.flush().await?;
            debug!(
                "Received a total of {} bytes, start installation",
                received_bytes
            );
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
    message_tx.send(msg_with_data).await;
    Ok(())
}

async fn send_reply<W: Unpin + Write>(reply: &Message, writer: &mut W) -> io::Result<()> {
    // Serialize reply
    let reply =
        serde_json::to_string_pretty(&reply).map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    // Send reply
    let mut buffer = [0u8; 4];
    BigEndian::write_u32(&mut buffer, reply.len() as u32);
    writer.write_all(&buffer).await?;
    writer.write_all(reply.as_bytes()).await?;
    Ok(())
}

fn start_sending_over_socket(writer: &TcpStream, client_rx: sync::Receiver<Message>) -> Result<()> {
    // setup send functionality
    let mut writer = writer.clone();
    let _ = task::spawn(async move {
        loop {
            match client_rx.recv().await {
                Ok(msg_to_send) => {
                    if let Err(e) = send_reply(&msg_to_send, &mut writer).await {
                        warn!("Error sending back to client: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    warn!("Error receiving send job: {}", e);
                    break;
                }
            }
        }
    });
    Ok(())
}

fn start_receiving_from_socket(
    reader: &TcpStream,
    tmp_installation_dir: std::path::PathBuf,
    message_tx: sync::Sender<MessageWithData>,
) -> Result<()> {
    let reader = reader.clone();
    let _ = task::spawn(async move {
        let mut buf_reader: io::BufReader<&TcpStream> = io::BufReader::new(&reader);
        // TODO listen for shutdown
        loop {
            if let Err(e) =
                receive_message_from_socket(&mut buf_reader, &message_tx, &tmp_installation_dir)
                    .await
            {
                warn!("Error receiving from socket: {}", e);
                break;
            }
        }
    });
    debug!("Stopped receiving from socket");
    Ok(())
}

async fn connection_loop(
    stream: TcpStream,
    mut event_tx: EventTx,
    notification_rx: NotificationRx,
) {
    let peer = match stream.peer_addr() {
        Ok(peer) => peer,
        Err(e) => {
            warn!("Failed to get peer from command connection: {}", e);
            return;
        }
    };
    debug!("Client {:?} connected", peer);

    enum ConsoleEvent {
        SystemEvent(SystemNotification),
        ApiMessage(MessageWithData),
    }

    let (reader, writer) = &mut (&stream, &stream);
    let (mut message_tx, mut message_rx) = sync::channel::<Message>(1);
    // channel for sending messages back to client
    let (client_tx, client_rx) = sync::channel::<Message>(1000);
    let (socket_tx, socket_rx) = sync::channel::<MessageWithData>(1);
    let tmp_installation_dir = tempdir().unwrap();
    start_receiving_from_socket(
        reader,
        std::path::PathBuf::from(tmp_installation_dir.path()),
        socket_tx,
    )
    .unwrap();

    start_sending_over_socket(writer, client_rx).unwrap();

    let message_event_stream: futures::stream::Map<async_std::sync::Receiver<MessageWithData>, _> =
        socket_rx.map(ConsoleEvent::ApiMessage);
    let runtime_event_stream: futures::stream::Map<
        async_std::sync::Receiver<SystemNotification>,
        _,
    > = notification_rx.map(ConsoleEvent::SystemEvent);
    let mut event_stream = futures::stream::select(message_event_stream, runtime_event_stream);

    while let Some(event) = event_stream.next().await {
        debug!("received something");
        match event {
            ConsoleEvent::SystemEvent(_notification) => {
                info!("handle system notification");
                let reply = Message {
                    id: "Notification".to_owned(),
                    payload: Payload::Notification(api::Notification {}),
                };
                client_tx.send(reply).await;
            }
            ConsoleEvent::ApiMessage(m) => {
                info!("handle ApiMessage");
                if let Err(e) = handle_api_request(
                    m,
                    client_tx.clone(),
                    &mut event_tx,
                    &mut message_rx,
                    &mut message_tx,
                )
                .await
                {
                    match e.kind() {
                        ErrorKind::UnexpectedEof => info!("Client {:?} disconnected", peer),
                        _ => warn!("Error on handle_request to {:?}: {:?}", peer, e),
                    }
                    break;
                }
            }
        }
    }

    async fn handle_api_request(
        m: MessageWithData,
        sender_to_client: Sender<Message>,
        event_tx: &mut EventTx,
        rx_reply: &mut Receiver<Message>,
        tx_reply: &mut Sender<Message>,
    ) -> io::Result<()> {
        let event = match m {
            MessageWithData {
                message:
                    Message {
                        id,
                        payload: Payload::Installation(_, name),
                    },
                path: Some(p),
            } => {
                info!("was installation");
                Event::Install(id, PathBuf::from(&p), name, tx_reply.clone())
            }
            _ => {
                info!("was consol event");
                Event::Console(m.message, tx_reply.clone())
            }
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
}
