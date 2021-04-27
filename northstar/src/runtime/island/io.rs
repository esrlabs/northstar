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
    super::pipe::{pipe, AsyncPipeRead, PipeWrite},
    Error,
};
use log::{debug, error, info, trace, warn, Level};
use npk::manifest::Manifest;
use std::{collections::HashMap, convert::TryInto, os::unix::prelude::AsRawFd};
use tokio::{io::AsyncBufReadExt, select, task};
use tokio_util::sync::CancellationToken;

/// Wrap the Rust log into a AsyncWrite
pub struct Log {
    pub(super) writer: PipeWrite,
    token: CancellationToken,
}

impl Log {
    pub async fn new(level: Level, tag: &str) -> Result<Log, Error> {
        let (reader, writer) = pipe().map_err(|e| Error::io("Failed to open pipe", e))?;
        let token = CancellationToken::new();
        let token_task = token.clone();
        let tag = tag.to_string();
        let async_reader: AsyncPipeRead = reader
            .try_into()
            .map_err(|e| Error::io("Failed to get async handler from pipe reader", e))?;

        task::spawn(async move {
            let mut reader = tokio::io::BufReader::new(async_reader).lines();

            loop {
                select! {
                    Ok(Some(line)) = reader.next_line() => {
                        let line = format!("{}: {}", tag, line);
                        match level {
                            Level::Trace => trace!("{}", line),
                            Level::Debug => debug!("{}", line),
                            Level::Info => info!("{}", line),
                            Level::Warn => warn!("{}", line),
                            Level::Error => error!("{}", line),
                        }
                    }
                    _ = token_task.cancelled() => break,
                    else => break,

                }
            }
        });

        Ok(Log { writer, token })
    }
}

impl Drop for Log {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

pub(super) async fn from_manifest(
    manifest: &Manifest,
) -> Result<(Option<Log>, Option<Log>, HashMap<i32, i32>), Error> {
    let mut child_fd_map = HashMap::new();
    if let Some(io) = manifest.io.as_ref() {
        let stdout = match io.stdout {
            Some(npk::manifest::Output::Pipe) => {
                child_fd_map.insert(nix::libc::STDOUT_FILENO, nix::libc::STDOUT_FILENO);
                None
            }
            Some(npk::manifest::Output::Log { level, ref tag }) => {
                let log = Log::new(level, tag).await?;
                trace!("Stdout pipe fd is {}", log.writer.as_raw_fd());
                child_fd_map.insert(nix::libc::STDOUT_FILENO, log.writer.as_raw_fd());
                Some(log)
            }
            None => None,
        };
        let stderr = match io.stderr {
            Some(npk::manifest::Output::Pipe) => {
                child_fd_map.insert(nix::libc::STDERR_FILENO, nix::libc::STDERR_FILENO);
                None
            }
            Some(npk::manifest::Output::Log { level, ref tag }) => {
                let log = Log::new(level, tag).await?;
                trace!("Stderr pipe fd is {}", log.writer.as_raw_fd());
                child_fd_map.insert(nix::libc::STDERR_FILENO, log.writer.as_raw_fd());
                Some(log)
            }
            None => None,
        };
        Ok((stdout, stderr, child_fd_map))
    } else {
        Ok((None, None, child_fd_map))
    }
}
