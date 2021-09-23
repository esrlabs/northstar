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
use crate::{
    npk,
    npk::manifest::{Manifest, Output},
    runtime::pipe::PipeWrite,
};
use bytes::{Buf, BufMut, BytesMut};
use log::{debug, error, info, trace, warn, Level};
use nix::libc;
use std::{
    collections::HashMap,
    convert::TryInto,
    os::unix::prelude::{AsRawFd, RawFd},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{self, AsyncWrite, BufReader},
    task,
};

/// Implement AsyncWrite and forwards lines to Rust log
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

// Writing ends for stdout/stderr
pub(super) struct Io {
    _stdout: Option<PipeWrite>,
    _stderr: Option<PipeWrite>,
}

#[derive(Debug)]
pub(super) enum Fd {
    // Close the fd
    Close,
    // Dup2 the the fd to fd
    Dup(i32),
}

pub(super) async fn from_manifest(
    manifest: &Manifest,
) -> Result<(Option<Io>, HashMap<RawFd, Fd>), Error> {
    let mut fds = HashMap::new();

    // The default of all fds inherited from the parent is to close it
    let mut proc_self_fd = tokio::fs::read_dir("/proc/self/fd")
        .await
        .map_err(|e| Error::io("Readdir", e))?;
    while let Ok(Some(e)) = proc_self_fd.next_entry().await {
        let file = e.file_name();
        let fd: i32 = file.to_str().unwrap().parse().unwrap(); // fds are always numeric
        fds.insert(fd as RawFd, Fd::Close);
    }
    drop(proc_self_fd);

    let mut stdout_stderr = |c: Option<&Output>, fd| {
        match c {
            Some(npk::manifest::Output::Pipe) => {
                // Do nothing with the stdout fd - just prevent remove it from the list of fds that
                // has been gathered above and instructs the init to close those fds.
                fds.remove(&fd);
                Result::<_, Error>::Ok(None)
            }
            Some(npk::manifest::Output::Log { level, ref tag }) => {
                // Create a pipe: the writing end is used in the child as stdout/stderr. The reading end is used in a LogSink
                let (reader, writer) = pipe().map_err(|e| Error::io("Failed to open pipe", e))?;
                let reader_fd = reader.as_raw_fd();
                let reader: AsyncPipeRead = reader
                    .try_into()
                    .map_err(|e| Error::io("Failed to get async handler from pipe reader", e))?;

                let mut reader = BufReader::new(reader);
                let tag = tag.to_string();
                let mut log_sink = LogSink::new(*level, &tag);
                task::spawn(async move {
                    drop(io::copy_buf(&mut reader, &mut log_sink).await);
                });

                // The read fd shall be closed in the child. It's used in the runtime only
                fds.insert(reader_fd, Fd::Close);

                // Remove fd that is set to be Fd::Close by default. fd is closed by dup2
                fds.remove(&writer.as_raw_fd());
                // The writing fd shall be dupped to 2
                fds.insert(fd, Fd::Dup(writer.as_raw_fd()));

                // Return the writer: Drop (that closes) it in the parent. Forget in the child.
                Ok(Some(writer))
            }
            None => Ok(None),
        }
    };

    if let Some(io) = manifest.io.as_ref() {
        let io = Some(Io {
            _stdout: stdout_stderr(io.stdout.as_ref(), libc::STDOUT_FILENO)?,
            _stderr: stdout_stderr(io.stdout.as_ref(), libc::STDERR_FILENO)?,
        });
        Ok((io, fds))
    } else {
        Ok((None, fds))
    }
}
