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

use anyhow::{Context, Result};
use std::{
    fs,
    io::{self, Write},
    iter,
    path::{Path, PathBuf},
    thread, time,
};
use structopt::StructOpt;

#[derive(StructOpt)]
enum TestCommands {
    Cat {
        #[structopt(parse(from_os_str))]
        path: PathBuf,
    },
    Crash,
    Echo {
        message: Vec<String>,
    },
    Write {
        message: String,
        path: PathBuf,
    },
    Touch {
        path: PathBuf,
    },
    Whoami,
    LeakMemory,
}

fn main() -> Result<()> {
    let input = Path::new("/data").join("input.txt");
    if input.exists() {
        println!("Reading {}", input.display());
        let commands = fs::read_to_string(&input)?;

        println!("Removing {}", input.display());
        fs::remove_file(&input)?;

        for line in commands.lines() {
            println!("Executing \"{}\"", line);
            let command = iter::once("test_container").chain(line.split_whitespace());
            match TestCommands::from_iter(command) {
                TestCommands::Cat { path } => cat(&path)?,
                TestCommands::Crash => crash(),
                TestCommands::Echo { message } => echo(&message),
                TestCommands::Write { message, path } => write(&message, path.as_path())?,
                TestCommands::Touch { path } => touch(&path)?,
                TestCommands::Whoami => whoami(),
                TestCommands::LeakMemory => leak_memory(),
            };
        }
    }

    println!("Sleeping...");
    thread::sleep(time::Duration::from_secs(u64::MAX));

    Ok(())
}

fn cat(path: &Path) -> Result<()> {
    let mut input =
        fs::File::open(&path).with_context(|| format!("Failed to open {}", path.display()))?;
    let mut output = std::io::stdout();
    io::copy(&mut input, &mut output)
        .map(drop)
        .with_context(|| format!("Failed to cat {}", path.display()))?;
    writeln!(&mut output).context("Failed to write to stdout")
}

fn echo(message: &[String]) {
    println!("{}", message.join(" "));
}

fn crash() {
    panic!("witness me!");
}

fn write(input: &str, path: &Path) -> Result<()> {
    fs::write(path, input).context(format!(
        "Failed to write \"{}\" to {}",
        input,
        path.display()
    ))
}

fn touch(path: &Path) -> Result<()> {
    fs::File::create(path)?;
    Ok(())
}

fn whoami() {
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();
    println!("uid: {}, gid: {}", uid, gid);
}

fn leak_memory() {
    for _ in 0..9_999_999 {
        println!("Eating a Megabyte...");
        let chunk: Vec<u8> = (0..1_000_000).map(|n| (n % 8) as u8).collect();
        std::mem::forget(chunk);
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
}
