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
use std::{fmt::Write, fs::File, io, io::BufRead, path::PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    /// Path to strace log file
    input: PathBuf,
}

fn main() -> Result<()> {
    env_logger::init();

    let opt = Opt::from_args();
    generate(opt.input)
}

fn generate(strace_file: PathBuf) -> Result<()> {
    let lines = open_file(strace_file);
    let names = parse_strace(lines);
    let entry = gen_seccomp_entry(names).expect("Failed to generate seccomp entry");
    println!("{}", &entry);
    Ok(())
}

fn open_file(strace_file: PathBuf) -> Vec<String> {
    let file = File::open(strace_file).expect("Failed to open strace input file");
    io::BufReader::new(file)
        .lines()
        .filter_map(|s| s.ok())
        .collect::<Vec<String>>()
}

fn parse_strace<I>(lines: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    // Collect syscall names and arguments
    let mut names = vec![];
    // unwrap(): Creating regex from constant expression will never fail
    let regex = Regex::new(r"^\s*(?:\[[^]]*]|\d+)?\s*([a-zA-Z0-9_]+)\(([^)<]*)").unwrap();
    for line in lines {
        if let Some(caps) = regex.captures(line.as_str()) {
            let name = caps.get(1).map_or("", |m| m.as_str());
            let _args = caps.get(2).map_or("", |m| m.as_str());
            names.push(name.to_string());
        }
    }
    // Filter duplicates while retaining order
    names.into_iter().unique().collect()
}

fn gen_seccomp_entry<I>(names: I) -> Result<String>
where
    I: IntoIterator<Item = String>,
{
    let mut entry = String::new();
    writeln!(&mut entry, "seccomp:")?;
    writeln!(&mut entry, "  allow:")?;
    for name in names {
        writeln!(&mut entry, "    {}: any", &name)?;
    }
    Ok(entry)
}

#[test]
fn parse_strace_log() {
    const EXPECTED: &str = "seccomp:
  allow:
    brk: any
    arch_prctl: any
    access: any
    openat: any
    newfstatat: any
    read: any
    mmap: any
    mprotect: any
    close: any
    pread64: any
    set_tid_address: any
    set_robust_list: any
    rt_sigaction: any
    rt_sigprocmask: any
    prlimit64: any
    poll: any
    sigaltstack: any
    sched_getaffinity: any
    write: any
    clock_nanosleep: any
    munmap: any
    exit_group: any
";
    let test_data = include_str!("../res/test_strace_data.txt");
    let lines = test_data
        .lines()
        .map(|s| s.to_string())
        .collect::<Vec<String>>();
    let names = parse_strace(lines);
    assert_eq!(22, names.len());
    let entry = gen_seccomp_entry(names).expect("Failed to generate seccomp entry");
    assert_eq!(&EXPECTED, &entry);
}
