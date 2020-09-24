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

//! Utils to execute assertions on process's standard output.

use anyhow::{Context, Result};
use async_std::{
    sync::{channel, Receiver},
    task,
};
use log::debug;
use regex::Regex;
use std::io::{self, BufRead, BufReader};

pub struct CaptureReader {
    receiver: Receiver<String>,
}

impl CaptureReader {
    /// Takes the stdout from the input process and wraps it in a CaptureReader
    pub async fn new<R: io::Read + Send + Sync + 'static>(read: R) -> CaptureReader {
        let (sender, receiver) = channel::<String>(100);

        task::spawn_blocking(move || {
            let stdout = BufReader::new(read);
            let mut lines = stdout.lines();
            while let Some(Ok(line)) = lines.next() {
                debug!("{}", line);
                task::block_on(sender.send(line));
            }
        });

        CaptureReader { receiver }
    }

    /// Consumes the stdout till a match to the input regex is found.
    pub async fn captures(&mut self, regex: &str) -> Result<Option<Vec<String>>> {
        let re = Regex::new(regex).context("invalid regular expression")?;
        while let Ok(line) = self.receiver.recv().await {
            if let Some(cap) = re.captures(&line) {
                return Ok(Some(
                    cap.iter()
                        .filter_map(|m| m.map(|s| s.as_str().to_owned()))
                        .collect(),
                ));
            }
        }
        Ok(None)
    }
}
