// Copyright (c) 2021 ESRLabs
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

use super::{
    super::pipe::{pipe, AsyncPipeRead},
    Error,
};
use bytes::{Buf, BufMut, BytesMut};
use futures::FutureExt;
use log::{debug, error, info, trace, warn, Level};
use nix::libc;
use npk::manifest::Manifest;
use std::{
    collections::HashMap,
    convert::TryInto,
    os::unix::prelude::{AsRawFd, IntoRawFd, RawFd},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{self, AsyncWrite, BufReader},
    pin, select,
    task::{self, JoinHandle},
};
use tokio_util::sync::CancellationToken;

/// Wrap the Rust log into a AsyncWrite
#[derive(Debug)]
pub struct Log {
    pub read_fd: RawFd,
    token: CancellationToken,
    task: JoinHandle<()>,
}

impl Log {
    pub async fn new(level: Level, tag: &str) -> Result<(Log, RawFd), Error> {
        let (reader, writer) = pipe().map_err(|e| Error::io("Failed to open pipe", e))?;
        let read_fd = reader.as_raw_fd();
        let reader: AsyncPipeRead = reader
            .try_into()
            .map_err(|e| Error::io("Failed to get async handler from pipe reader", e))?;

        let mut reader = BufReader::new(reader);
        let tag = tag.to_string();
        let token = CancellationToken::new();
        let token_task = token.clone();

        let task = task::spawn(async move {
            let mut log_sink = LogSink::new(level, &tag);
            let copy = io::copy_buf(&mut reader, &mut log_sink).map(drop);
            pin!(copy);
            select! {
                _ = token_task.cancelled() => {
                    debug!("Stopped log task of {}", tag);
                },
                _ = copy => (),
            }
        });

        Ok((
            Log {
                read_fd,
                token,
                task,
            },
            writer.into_raw_fd(),
        ))
    }

    pub async fn stop(self) -> Result<(), Error> {
        // Stop the forwarding task started in Log::new
        self.token.cancel();
        // Wait for the task to exit
        self.task
            .await
            .map_err(|e| Error::io("Task join error", io::Error::new(io::ErrorKind::Other, e)))
    }
}

struct LogSink {
    buffer: BytesMut,
    level: Level,
    tag: String,
}

impl LogSink {
    fn new(level: Level, tag: &str) -> LogSink {
        LogSink {
            level,
            tag: tag.to_string(),
            buffer: BytesMut::new(),
        }
    }
}

impl LogSink {
    fn log(&mut self) {
        while let Some(p) = self.buffer.iter().position(|b| *b == b'\n') {
            let line = self.buffer.split_to(p);
            // Discard the newline
            self.buffer.advance(1);
            let line = String::from_utf8_lossy(&line);
            match self.level {
                Level::Trace => trace!("{}: {}", self.tag, line),
                Level::Debug => debug!("{}: {}", self.tag, line),
                Level::Info => info!("{}: {}", self.tag, line),
                Level::Warn => warn!("{}: {}", self.tag, line),
                Level::Error => error!("{}: {}", self.tag, line),
            }
        }
    }
}

impl AsyncWrite for LogSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.buffer.extend(buf);
        self.log();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        // Log even unfinished lines received until now by adding a newline and print
        self.buffer.reserve(1);
        self.buffer.put_u8(b'\n');
        self.log();
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug)]
pub(super) enum Fd {
    /// Do not close this fd and use as it is
    Inherit,
    // Close the fd
    Close,
    // Dup2 the the fd to fd
    Dup(i32),
}

pub(super) async fn from_manifest(
    manifest: &Manifest,
) -> Result<(Option<(Log, RawFd)>, Option<(Log, RawFd)>, Vec<(RawFd, Fd)>), Error> {
    let mut fd_configuration = HashMap::new();

    // The default of all fds inherited from the parent is to close it
    let mut fds = tokio::fs::read_dir("/proc/self/fd")
        .await
        .map_err(|e| Error::io("Readdir", e))?;
    while let Ok(Some(e)) = fds.next_entry().await {
        let file = e.file_name();
        let fd: i32 = file.to_str().unwrap().parse().unwrap(); // fds are always numeric
        fd_configuration.insert(fd as RawFd, Fd::Close);
    }
    drop(fds);

    if let Some(io) = manifest.io.as_ref() {
        let stdout = match io.stdout {
            Some(npk::manifest::Output::Pipe) => {
                fd_configuration.insert(libc::STDOUT_FILENO, Fd::Inherit);
                None
            }
            Some(npk::manifest::Output::Log { level, ref tag }) => {
                let (log, fd) = Log::new(level, tag).await?;
                // The read fd shall be closed in the child
                fd_configuration.insert(log.read_fd, Fd::Close);
                // Remove fd that is set to be Fd::Close by default. fd is closed by dup2
                fd_configuration.remove(&fd);
                // The writing fd shall be dupped to 1
                fd_configuration.insert(libc::STDOUT_FILENO, Fd::Dup(fd));
                Some((log, fd))
            }
            None => None,
        };
        let stderr = match io.stderr {
            Some(npk::manifest::Output::Pipe) => {
                fd_configuration.insert(libc::STDERR_FILENO, Fd::Inherit);
                None
            }
            Some(npk::manifest::Output::Log { level, ref tag }) => {
                let (log, fd) = Log::new(level, tag).await?;
                // The read fd shall be closed in the child
                fd_configuration.insert(log.read_fd, Fd::Close);
                // Remove fd that is set to be Fd::Close by default. fd is closed by dup2
                fd_configuration.remove(&fd);
                // The writing fd shall be dupped to 2
                fd_configuration.insert(libc::STDERR_FILENO, Fd::Dup(fd));
                Some((log, fd))
            }
            None => None,
        };
        Ok((stdout, stderr, fd_configuration.drain().collect()))
    } else {
        Ok((None, None, fd_configuration.drain().collect()))
    }
}
