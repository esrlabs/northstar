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

//! Extends Future with timeout methods

use color_eyre::eyre::{Result, WrapErr};
use log::debug;
use regex::Regex;
use std::{env, path::PathBuf};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    stream::StreamExt,
    sync::mpsc::{channel, Receiver},
    task,
};

pub struct CaptureReader {
    receiver: Receiver<String>,
}

impl CaptureReader {
    /// Takes the stdout from the input process and wraps it in a CaptureReader
    pub async fn new<R: AsyncRead + Send + Sync + Unpin + 'static>(read: R) -> CaptureReader {
        let (sender, receiver) = channel::<String>(100);

        task::spawn(async move {
            let stdout = BufReader::new(read);
            let mut lines = stdout.lines();
            while let Some(Ok(line)) = lines.next().await {
                debug!("{}", line);
                sender.send(line).await.ok();
            }
        });

        CaptureReader { receiver }
    }

    /// Consumes the stdout till a match to the input regex is found.
    pub async fn captures(&mut self, regex: &str) -> Result<Option<Vec<String>>> {
        let re = Regex::new(regex).wrap_err("Invalid regular expression")?;
        while let Some(line) = self.receiver.recv().await {
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

pub fn cargo_bin<S: AsRef<str>>(name: S) -> PathBuf {
    let path = cargo_bin_str(name.as_ref());
    if !path.exists() {
        panic!("Required binary {} does not exist", path.display());
    }
    path
}

fn target_dir() -> PathBuf {
    env::current_exe()
        .ok()
        .map(|mut path| {
            path.pop();
            if path.ends_with("deps") {
                path.pop();
            }
            path
        })
        .unwrap()
}

fn cargo_bin_str(name: &str) -> PathBuf {
    target_dir().join(format!("{}{}", name, env::consts::EXE_SUFFIX))
}
