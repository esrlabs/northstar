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

use anyhow::Result;
use itertools::Itertools;
use regex::Regex;
use std::fmt::Write;
use std::{fs::File, io, io::BufRead, path::PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
enum Opt {
    /// Generate seccomp manifest entry
    Generate {
        /// Path to strace log file
        #[structopt(short, long)]
        strace_file: PathBuf,
    },
}

fn main() -> Result<()> {
    env_logger::init();

    match Opt::from_args() {
        Opt::Generate { strace_file } => generate(strace_file)?,
    }
    Ok(())
}

fn generate(strace_file: PathBuf) -> Result<()> {
    let names = parse_strace(strace_file);
    let entry = gen_seccomp_entry(&names).expect("Failed to generate seccomp entry");
    println!("{}", &entry);
    Ok(())
}

fn parse_strace(strace_file: PathBuf) -> Vec<String> {
    let file = File::open(strace_file).expect("Failed to open strace input file");
    let lines = io::BufReader::new(file).lines();

    // Collect syscall names and arguments
    let mut names = vec![];
    // unwrap(): Creating regex from constant expression will never fail
    let regex = Regex::new(r"^\s*(?:\[[^]]*]|\d+)?\s*([a-zA-Z0-9_]+)\(([^)<]*)").unwrap();
    for line in lines.flatten() {
        if let Some(caps) = regex.captures(line.as_str()) {
            let name = caps.get(1).map_or("", |m| m.as_str());
            let _args = caps.get(2).map_or("", |m| m.as_str());
            names.push(name.to_string());
        }
    }
    // Filter duplicates while retaining order
    names.into_iter().unique().collect()
}

fn gen_seccomp_entry(names: &[String]) -> Result<String> {
    let mut entry = String::new();
    writeln!(&mut entry, "seccomp:")?;
    writeln!(&mut entry, "  allow:")?;
    for name in names {
        writeln!(&mut entry, "    {}: any", &name)?;
    }
    Ok(entry)
}
