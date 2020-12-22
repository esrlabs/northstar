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

use color_eyre::eyre::{Result, WrapErr};
use colored::Colorize;
use lazy_static::lazy_static;
use log::{Level, Metadata, Record};
use regex::Regex;
use std::{collections::VecDeque, sync::Mutex, time::Duration};
use tokio::{task, time};

lazy_static! {
    static ref LOG_BUFFER: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
}

pub struct LogParser;

impl log::Log for LogParser {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        fn level_format(level: Level) -> String {
            let level = match level {
                Level::Error => "E".red(),
                Level::Warn => "W".truecolor(255, 69, 0),
                Level::Info => "I".normal(),
                Level::Debug => "D".green(),
                Level::Trace => "T".yellow(),
            };
            format!("{} {} {}", "[".blue().bold(), level, "]".blue().bold())
        }

        fn message_format(record: &Record) -> String {
            let args = record.args().to_string();
            match record.level() {
                Level::Error => format!("{}", args.red()),
                Level::Warn => format!("{}", args.truecolor(255, 69, 0)),
                _ => format!("{}", args.normal()),
            }
        }

        let level = record.level();
        println!("{} {}", level_format(level), message_format(record));

        LOG_BUFFER
            .lock()
            .unwrap()
            .push_back(format!("{}", record.args()));
    }

    fn flush(&self) {}
}

pub async fn assume(pattern: &str, timeout: Duration) -> Result<()> {
    let regex = Regex::new(pattern).expect("Invalid regex");
    let consume_log = task::spawn_blocking(move || loop {
        if let Some(line) = LOG_BUFFER.lock().unwrap().pop_front() {
            if regex.is_match(&line) {
                break;
            }
        }
    });
    time::timeout(timeout, consume_log)
        .await
        .wrap_err(format!(
            "Failed to find pattern \"{}\" in log output",
            pattern
        ))
        .and_then(|r| r.wrap_err("Failed to join log parsing blocking call"))
}
