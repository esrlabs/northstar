// Copyright (c) 2019 - 2021 ESRLabs
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

use anyhow::{Context, Result};
use northstar::{
    common::non_null_string::NonNullString,
    npk::manifest::{Seccomp, SyscallRule},
};
use regex::Regex;
use std::{collections::HashMap, convert::TryFrom, fs::File, io, io::BufRead, path::PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    /// Path to strace log file
    input: PathBuf,
}

fn main() -> Result<()> {
    env_logger::init();

    // Open strace log
    let path: PathBuf = Opt::from_args().input;
    let file =
        File::open(&path).context(format!("Failed to open strace log: {}", &path.display()))?;

    // Collect syscall names
    let mut syscalls: HashMap<NonNullString, SyscallRule> = HashMap::new();
    // unwrap(): Creating regex from constant expression will never fail
    let regex = Regex::new(r"^\s*(?:\[[^]]*]|\d+)?\s*([a-zA-Z0-9_]+)\(([^)<]*)").unwrap();
    io::BufReader::new(file)
        .lines()
        .try_for_each(|line| -> Result<()> {
            if let Some(caps) = regex.captures(line?.as_str()) {
                if let Some(m) = caps.get(1) {
                    syscalls.insert(NonNullString::try_from(m.as_str())?, SyscallRule::Any);
                }
            }
            Ok(())
        })?;
    let entry = Seccomp {
        profile: None,
        allow: Some(syscalls),
    };
    println!("{}", &serde_yaml::to_string(&entry)?);
    Ok(())
}
