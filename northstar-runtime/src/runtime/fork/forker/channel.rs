use std::{iter::once, os::unix::prelude::OwnedFd};

use crate::{
    common::{container::Container, non_nul_string::NonNulString},
    runtime::{
        fork::init::Init,
        ipc::{AsyncFramedUnixStream, FramedUnixStream},
        runtime::Pid,
    },
};
use serde::{Deserialize, Serialize};

use super::Message;

/// Command and socket stream bundled in one entity.
#[derive(Debug)]
pub struct Channel {
    /// Socket for message communication.
    command: AsyncFramedUnixStream,
    /// Socket for file descriptor transfer.
    socket: FramedUnixStream,
}

impl Channel {
    /// Construct a new Channel struct.
    pub fn new(command: AsyncFramedUnixStream, socket: FramedUnixStream) -> Channel {
        Channel { command, socket }
    }

    /// Send Message via command and socket stream.
    pub async fn send(&mut self, message: Message) {
        match message {
            Message::CreateRequest { init, io, console } => {
                let message = SerdeMessage::CreateRequest { init };
                self.command
                    .send(message)
                    .await
                    .expect("failed to send response");

                // Send file descriptors. The console fd is optional.
                if let Some(console) = console {
                    let fds: Vec<_> = io.into_iter().chain(once(console)).collect();
                    self.socket.send_fds(&fds).expect("failed to send fds");
                } else {
                    self.socket.send_fds(&io).expect("failed to send fds");
                }
            }
            m => {
                let message: SerdeMessage = m.into();
                self.command
                    .send(message)
                    .await
                    .expect("failed to send response");
            }
        }
    }

    pub async fn recv(&mut self) -> Option<Message> {
        match self.command.recv().await.ok()?? {
            SerdeMessage::CreateRequest { init } => {
                // Receive file descriptors.
                if init.console {
                    let mut fds = self
                        .socket
                        .recv_fds::<OwnedFd, 4>()
                        .expect("failed to receive fds");
                    let console = fds.pop();
                    let io = fds.try_into().expect("invalid number of fds");
                    Some(Message::CreateRequest { init, io, console })
                } else {
                    let io = self
                        .socket
                        .recv_fds::<OwnedFd, 3>()
                        .expect("failed to receive fds");
                    let io = io.try_into().expect("invalid number of fds received");
                    Some(Message::CreateRequest {
                        init,
                        io,
                        console: None,
                    })
                }
            }
            message => Some(message.into()),
        }
    }
}

/// Message type that implements Serialize and Deserialize (wihout OwnedFd fields).
#[derive(Debug, Serialize, Deserialize)]
enum SerdeMessage {
    CreateRequest {
        init: Init,
    },
    /// Result of a container creation.
    CreateResult {
        result: Result<Pid, String>,
    },
    /// Perfrom an exec from a container init with the given arguments.
    ExecRequest {
        container: Container,
        path: NonNulString,
        args: Vec<NonNulString>,
        env: Vec<NonNulString>,
    },
    /// Confirmation message for a exec request.
    ExecResult,
}

impl From<Message> for SerdeMessage {
    fn from(message: Message) -> Self {
        match message {
            Message::CreateRequest { init, .. } => SerdeMessage::CreateRequest { init },
            Message::CreateResult { result } => SerdeMessage::CreateResult { result },
            Message::ExecRequest {
                container,
                path,
                args,
                env,
            } => SerdeMessage::ExecRequest {
                container,
                path,
                args,
                env,
            },
            Message::ExecResult => SerdeMessage::ExecResult,
        }
    }
}

impl From<SerdeMessage> for Message {
    fn from(message: SerdeMessage) -> Self {
        match message {
            SerdeMessage::CreateRequest { .. } => {
                unreachable!("this shall never happen and is a bug")
            }
            SerdeMessage::CreateResult { result } => Message::CreateResult { result },
            SerdeMessage::ExecRequest {
                container,
                path,
                args,
                env,
            } => Message::ExecRequest {
                container,
                path,
                args,
                env,
            },
            SerdeMessage::ExecResult => Message::ExecResult,
        }
    }
}
