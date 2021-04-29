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

use anyhow::{anyhow, Context, Result};
use lazy_static::lazy_static;
use log::{debug, warn};
use regex::Regex;
use std::{
    fmt,
    io::Write,
    time::{Duration, Instant},
};
use tokio::{pin, select, time};

lazy_static! {
    static ref QUEUE: (
        std::sync::Mutex<flume::Sender<String>>,
        tokio::sync::Mutex<flume::Receiver<String>>
    ) = {
        let (tx, rx) = flume::unbounded();
        (std::sync::Mutex::new(tx), tokio::sync::Mutex::new(rx))
    };
    static ref START: Instant = Instant::now();
}

pub fn init() {
    let mut builder = env_logger::Builder::new();
    builder.parse_filters("debug");

    builder.format(|buf, record| {
        let tx = QUEUE.0.lock().unwrap();
        tx.send(record.args().to_string()).expect("Channel error");

        let timestamp = buf.timestamp_millis();
        let level = buf.default_styled_level(record.metadata().level());

        if let Some(module_path) = record
            .module_path()
            .and_then(|module_path| module_path.find(&"::").map(|p| &module_path[p + 2..]))
        {
            writeln!(
                buf,
                "{}: {:<5}: {} {}",
                timestamp,
                level,
                module_path,
                record.args(),
            )
        } else {
            writeln!(buf, "{}: {:<5}: {}", timestamp, level, record.args(),)
        }
    });

    builder.init()
}

/// Assume the runtime to log a line matching `pattern` within
/// `timeout` seconds.
pub async fn assume<T: ToString + fmt::Display>(pattern: T, timeout: u64) -> Result<()> {
    let regex = Regex::new(&pattern.to_string()).context("Invalid regex")?;
    let timeout = time::sleep(Duration::from_secs(timeout));
    pin!(timeout);

    let rx = QUEUE.1.lock().await;

    loop {
        select! {
            _ = &mut timeout => {
                warn!("Log assumption \"{}\" timeout", pattern);
                return Err(anyhow!("Timeout waiting for \"{}\"", pattern));
            }
            log = rx.recv_async() => {
                match log {
                    Ok(n) if regex.is_match(&n) => {
                        debug!("Log assumption \"{}\" success", pattern);
                        break Ok(());
                    }
                    Ok(_) => continue,
                    Err(_) => break Err(anyhow!("Internal error")),
                }
            }
        }
    }
}
