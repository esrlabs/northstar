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
}

#[allow(clippy::all)]
fn main() -> Result<()> {
    let data = Path::new("/data").join("input.txt");
    let commands = fs::read_to_string(&data)
        .with_context(|| format!("Failed to read commands from {}", data.display()))?;

    // Execute commands
    for command in commands.lines() {
        println!("Executing command \"{}\"", command);
        let command = iter::once("test_container").chain(command.split_whitespace());
        match TestCommands::from_iter(command) {
            TestCommands::Cat { path } => cat(&path)?,
            TestCommands::Crash => crash(),
            TestCommands::Echo { message } => echo(&message),
            TestCommands::Write { message, path } => write(&message, path.as_path())?,
            TestCommands::Touch { path } => touch(&path)?,
        };
    }

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
