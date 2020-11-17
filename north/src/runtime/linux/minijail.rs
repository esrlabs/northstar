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

use log::Level;
use nix::unistd::pipe;
use std::os::unix::prelude::FromRawFd;
use thiserror::Error;
use tokio::{
    fs,
    io::{self, AsyncBufReadExt},
    stream::StreamExt,
    task,
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Init error: {0}")]
    Init(#[from] nix::Error),
}

/// Initialize minijail logging
pub async fn init() -> Result<(), Error> {
    #[allow(non_camel_case_types)]
    #[allow(dead_code)]
    #[repr(i32)]
    enum SyslogLevel {
        LOG_EMERG = 0,
        LOG_ALERT = 1,
        LOG_CRIT = 2,
        LOG_ERR = 3,
        LOG_WARNING = 4,
        LOG_NOTICE = 5,
        LOG_INFO = 6,
        LOG_DEBUG = 7,
        MAX = i32::MAX,
    }

    if let Some(log_level) = log::max_level().to_level() {
        let minijail_log_level = match log_level {
            Level::Error => SyslogLevel::LOG_ERR,
            Level::Warn => SyslogLevel::LOG_WARNING,
            Level::Info => SyslogLevel::LOG_INFO,
            Level::Debug => SyslogLevel::LOG_DEBUG,
            Level::Trace => SyslogLevel::MAX,
        };

        let (readfd, writefd) = pipe().map_err(Error::Init)?;

        let pipe = unsafe { fs::File::from_raw_fd(readfd) };
        minijail::Minijail::log_to_fd(writefd, minijail_log_level as i32);

        let mut lines = io::BufReader::new(pipe).lines();
        task::spawn(async move {
            while let Some(Ok(line)) = lines.next().await {
                // TODO: Format the logs to make them seemless
                log::log!(log_level, "{}", line);
            }
        });
    }

    Ok(())
}
