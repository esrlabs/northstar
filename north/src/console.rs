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
    runtime::{Event, EventTx, TerminationReason},
    state::State,
};
use anyhow::{Context, Result};
use api::{
    Container, Message, Payload, Process, Request, Response, ShutdownResult, StartResult,
    StopResult,
};
use async_std::{
    io::{self, Write},
    net::TcpListener,
    prelude::*,
    sync::{self, Receiver, Sender},
    task,
};
use byteorder::{BigEndian, ByteOrder};
use io::{ErrorKind, Read};
use log::{debug, info, warn};

pub async fn init(address: &str, tx: &EventTx) -> Result<()> {
    serve(address, tx.clone()).await?;
    Ok(())
}

pub async fn process(
    state: &mut State,
    message: &Message,
    response_tx: sync::Sender<Message>,
) -> Result<()> {
    let payload = &message.payload;
    if let Payload::Request(ref request) = payload {
        let response = match request {
            Request::Containers => {
                let containers = state
                    .applications()
                    .map(|app| {
                        Container {
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
                Err(e) => Response::Start {
                    result: StartResult::Error(e.to_string()),
                },
            },
            Request::Stop(name) => {
                match state
                    .stop(
                        &name,
                        std::time::Duration::from_secs(1),
                        TerminationReason::Stopped,
                    )
                    .await
                {
                    Ok(_) => Response::Stop {
                        result: StopResult::Success,
                    },
                    Err(e) => Response::Stop {
                        result: StopResult::Error(e.to_string()),
                    },
                }
            }
            Request::Install(_) => Response::Install {
                result: api::InstallationResult::Error("unimplemented".into()),
            },
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
async fn serve(address: &str, tx: EventTx) -> Result<()> {
    debug!("Starting console on {}", address);

    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("Failed to open listener on {}", address))?;

    task::spawn(async move {
        let mut incoming = listener.incoming();

        // Spawn a task for each incoming connection.
        while let Some(stream) = incoming.next().await {
            let mut tx_main = tx.clone();
            if let Ok(stream) = stream {
                let peer = match stream.peer_addr() {
                    Ok(peer) => peer,
                    Err(e) => {
                        warn!("Failed to get peer from command connection: {}", e);
                        continue;
                    }
                };
                debug!("Client {:?} connected", peer);

                // Spawn a task that handles this client
                task::spawn(async move {
                    let (reader, writer) = &mut (&stream, &stream);
                    let mut reader = io::BufReader::new(reader);
                    let (mut tx, mut rx) = sync::channel::<Message>(10);

                    loop {
                        if let Err(e) =
                            connection(&mut reader, writer, &mut tx_main, &mut rx, &mut tx).await
                        {
                            match e.kind() {
                                ErrorKind::UnexpectedEof => info!("Client {:?} disconnected", peer),
                                _ => warn!("Error on connection to {:?}: {:?}", peer, e),
                            }
                            break;
                        }
                    }
                });
            }
        }
    });
    Ok(())
}

async fn connection<R: Unpin + Read, W: Unpin + Write>(
    reader: &mut R,
    writer: &mut W,
    tx: &mut EventTx,
    rx_reply: &mut Receiver<Message>,
    tx_reply: &mut Sender<Message>,
) -> io::Result<()> {
    // Read frame length
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf).await?;
    let frame_len = BigEndian::read_u32(&buf) as usize;

    // Read payload
    let mut buffer = vec![0; frame_len];
    reader.read_exact(&mut buffer).await?;

    // Deserialize message
    let message: Message = serde_json::from_slice(&buffer)?;

    // Send message and response handle to main loop
    tx.send(Event::Console(message, tx_reply.clone())).await;

    // Wait for reply of main loop
    // TODO: timeout
    let reply = rx_reply
        .recv()
        .await
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

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
