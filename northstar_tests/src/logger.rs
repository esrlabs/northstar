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

use color_eyre::eyre::{eyre, Result};
use colored::Colorize;
use lazy_static::lazy_static;
use log::{Level, Metadata, Record};
use regex::Regex;
use std::{
    sync::{self, mpsc},
    time::{Duration, Instant},
};
use tokio::{select, task::spawn_blocking, time};

lazy_static! {
    static ref QUEUE: (
        sync::Mutex<mpsc::Sender<String>>,
        sync::Mutex<mpsc::Receiver<String>>
    ) = {
        let (tx, rx) = mpsc::channel::<String>();
        (sync::Mutex::new(tx), sync::Mutex::new(rx))
    };
    static ref START: Instant = Instant::now();
}

pub struct LogParser;

impl log::Log for LogParser {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        fn level_format(level: Level) -> String {
            match level {
                Level::Error => "E".red(),
                Level::Warn => "W".truecolor(255, 69, 0),
                Level::Info => "I".normal(),
                Level::Debug => "D".green(),
                Level::Trace => "T".yellow(),
            }
            .to_string()
        }

        let start = *START;

        println!(
            "{:010} {} {}: {}",
            Instant::now().duration_since(start).as_millis(),
            level_format(record.level()),
            record.module_path().unwrap_or(""),
            record.args().to_string()
        );

        QUEUE
            .0
            .lock()
            .unwrap()
            .send(record.args().to_string())
            .expect("Logger queue error")
    }

    fn flush(&self) {}
}

/// Clear the logger queue prior to each test run
pub fn reset() {
    let queue = QUEUE.1.lock().expect("Failed to lock log queue");
    while queue.try_recv().is_ok() {}
}

/// Assume the runtime to log a line matching `pattern` within
/// `timeout` seconds.
pub async fn assume(pattern: &'static str, timeout: u64) -> Result<()> {
    let assumption = spawn_blocking(move || loop {
        let regex = Regex::new(&pattern).expect("Invalid regex");
        match QUEUE.1.lock().unwrap().recv() {
            Ok(n) if regex.is_match(&n) => break Ok(()),
            Ok(_) => continue,
            Err(e) => break Err(e),
        }
    });

    let timeout = time::sleep(Duration::from_secs(timeout));
    select! {
        _ = timeout => Err(eyre!("Timeout waiting for {}", pattern)),
        _ = assumption => Ok(()),
    }
}
