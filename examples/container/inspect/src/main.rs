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

use nix::{libc::c_int, unistd};
use signal_hook::{consts::signal::*, low_level};
use std::{env, fs};

type Signals =
    signal_hook::iterator::SignalsInfo<signal_hook::iterator::exfiltrator::origin::WithOrigin>;

const SIGNALS: &[c_int] = &[
    SIGTERM, SIGQUIT, SIGINT, SIGTSTP, SIGWINCH, SIGHUP, SIGCHLD, SIGCONT,
];

fn dump(file: &str)  {
    println!("{}:", file);
    fs::read_to_string(file)
        .expect(&format!("dump {}", file))
        .lines()
        .for_each(|l| println!("  {}", l));
}

fn main() {
    env::set_var("RUST_BACKTRACE", "1");

    println!("getpid: {}", unistd::getpid());
    println!("getppid: {}", unistd::getppid());
    println!("getuid: {}", unistd::getuid());
    println!("getgid: {}", unistd::getgid());
    let pwd = env::current_dir().expect("current_dir");
    println!("pwd: {}", pwd.display());
    let exe = env::current_exe().expect("current_exe");
    println!("exe: {}", exe.display());

    dump("/proc/self/mounts");
    dump("/proc/self/environ");

    println!("fds:");
    for entry in fs::read_dir("/proc/self/fd").expect("read_dir /proc/self/fd") {
        let entry = entry.unwrap().path();
        let link = fs::read_link(&entry).expect("mount entry");
        println!("    {}: {}", entry.display(), link.display());
    }

    println!(
        "caps: {:?}",
        caps::read(None, caps::CapSet::Bounding).expect("Failed to read caps")
    );

    let mut sigs = Signals::new(SIGNALS).expect("install signal handler");
    for signal in &mut sigs {
        eprintln!("Received signal {:?}", signal);
        let signal = signal.signal;
        low_level::emulate_default_handler(signal).expect("default signal handler");
    }
}
