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

use caps::CapSet;
use nix::unistd::{self, Gid};
use std::{env, fs};

fn dump(file: &str) {
    println!("{}:", file);
    fs::read_to_string(file)
        .unwrap_or_else(|_| panic!("dump {}", file))
        .lines()
        .for_each(|l| println!("  {}", l));
}

fn main() {
    env::set_var("RUST_BACKTRACE", "1");

    println!("getpid: {}", unistd::getpid());
    println!("getppid: {}", unistd::getppid());
    println!("getuid: {}", unistd::getuid());
    println!("getgid: {}", unistd::getgid());
    println!("getsid: {}", unistd::getsid(None).unwrap());
    println!("getpgid: {}", unistd::getpgid(None).unwrap());
    println!(
        "getgroups: {:?}",
        unistd::getgroups()
            .expect("getgroups")
            .iter()
            .cloned()
            .map(Gid::as_raw)
            .collect::<Vec<_>>()
    );
    let pwd = env::current_dir().expect("current_dir");
    println!("pwd: {}", pwd.display());
    let exe = env::current_exe().expect("current_exe");
    println!("exe: {}", exe.display());

    dump("/proc/self/mounts");
    dump("/proc/self/environ");

    println!("fds:");
    for entry in fs::read_dir("/proc/self/fd").expect("read_dir /proc/self/fd") {
        let entry = entry.unwrap().path();
        let link = fs::read_link(&entry).expect("readlink");
        println!("    {}: {}", entry.display(), link.display());
    }

    for set in &[
        CapSet::Ambient,
        CapSet::Bounding,
        CapSet::Effective,
        CapSet::Inheritable,
        CapSet::Permitted,
    ] {
        println!(
            "caps {}: {:?}",
            format!("{:?}", set).as_str().to_lowercase(),
            caps::read(None, *set).expect("Failed to read caps")
        );
    }

    println!("ps:");
    for entry in fs::read_dir("/proc").expect("read_dir /proc") {
        let entry = entry.unwrap().path();
        if !entry.is_dir() {
            continue;
        }
        let pid = entry.file_name().unwrap().to_str().unwrap();
        let pid = match pid.parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };

        let stat = std::fs::read_to_string(entry.join("stat")).expect("read stat");
        let cmdline = std::fs::read_to_string(entry.join("cmdline")).expect("read cmdline");
        let name = stat
            .split_whitespace()
            .nth(1)
            .unwrap()
            .trim_start_matches('(')
            .trim_end_matches(')');
        println!("{:>8}: {:>10}: {}", pid, name, cmdline);
    }

    loop {
        unistd::pause();
    }
}
