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
use nix::unistd::{self, Gid};
use northstar::api::{client::Client, model::Version};
use std::{
    env,
    ffi::c_void,
    iter,
    path::{Path, PathBuf},
    process::{self, abort},
    thread,
};
use structopt::StructOpt;
use tokio::{fs, io, time};

#[derive(StructOpt)]
enum TestCommands {
    Abort,
    Cat {
        #[structopt(parse(from_os_str))]
        path: PathBuf,
    },
    Console,
    Echo {
        message: Vec<String>,
    },
    Inspect,
    LeakMemory,
    Touch {
        path: PathBuf,
    },
    Sleep {
        seconds: u64,
    },
    Write {
        message: String,
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let input = Path::new("/data").join("input.txt");
    if input.exists() {
        println!("Reading {}", input.display());
        let commands = fs::read_to_string(&input).await?;

        println!("Removing {}", input.display());
        fs::remove_file(&input).await?;

        for line in commands.lines() {
            println!("Executing \"{}\"", line);
            let command = iter::once("test-container").chain(line.split_whitespace());
            match TestCommands::from_iter(command) {
                TestCommands::Abort => abort(),
                TestCommands::Cat { path } => cat(&path).await?,
                TestCommands::Console => console().await,
                TestCommands::Echo { message } => echo(&message),
                TestCommands::Inspect => inspect().await,
                TestCommands::LeakMemory => leak_memory(),
                TestCommands::Touch { path } => touch(&path).await?,
                TestCommands::Sleep { seconds } => sleep(seconds).await,
                TestCommands::Write { message, path } => write(&message, path.as_path()).await?,
            };
        }
    }

    println!("Sleeping...");
    thread::sleep(time::Duration::from_secs(u64::MAX));

    Ok(())
}

async fn dump(file: &str) {
    println!("{}:", file);
    fs::read_to_string(file)
        .await
        .unwrap_or_else(|_| panic!("dump {}", file))
        .lines()
        .for_each(|l| println!("  {}", l));
}

async fn cat(path: &Path) -> Result<()> {
    let mut input = fs::File::open(&path)
        .await
        .with_context(|| format!("Failed to open {}", path.display()))?;
    let mut output = io::stdout();
    io::copy(&mut input, &mut output)
        .await
        .map(drop)
        .with_context(|| format!("Failed to cat {}", path.display()))
}

async fn console() {
    let url = url::Url::parse("unix:///northstar/console").unwrap();
    let mut client = Client::new(&url, None, time::Duration::from_secs(1))
        .await
        .expect("Failed to connect to northstar");
    client
        .stop(
            "test-container",
            &Version::parse("0.0.1").unwrap(),
            time::Duration::from_secs(1),
        )
        .await
        .expect("Failed to stop myself");
}

fn echo(message: &[String]) {
    println!("{}", message.join(" "));
}

async fn write(input: &str, path: &Path) -> Result<()> {
    fs::write(path, input)
        .await
        .with_context(|| format!("Failed to write \"{}\" to {}", input, path.display()))
}

async fn touch(path: &Path) -> Result<()> {
    fs::File::create(path).await.map(drop).map_err(Into::into)
}

fn leak_memory() {
    extern "C" {
        fn malloc(size: usize) -> *mut c_void;
    }

    loop {
        unsafe { malloc(1_000) };
    }
}

async fn inspect() {
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
    println!(
        "pwd: {}",
        env::current_dir().expect("current_dir").display()
    );
    println!(
        "exe: {}",
        env::current_exe().expect("current_exe").display()
    );

    for set in &[
        caps::CapSet::Ambient,
        caps::CapSet::Bounding,
        caps::CapSet::Effective,
        caps::CapSet::Inheritable,
        caps::CapSet::Permitted,
    ] {
        println!(
            "caps {}: {:?}",
            format!("{:?}", set).as_str().to_lowercase(),
            caps::read(None, *set).expect("Failed to read caps")
        );
    }

    println!("/proc/self/fd:");
    let mut n = 0;
    let mut read_dir = fs::read_dir("/proc/self/fd")
        .await
        .expect("Failed to readdir");
    while let Ok(Some(entry)) = read_dir.next_entry().await {
        let link = fs::read_link(entry.path())
            .await
            .expect("Failed to readlink");
        if link != PathBuf::from(format!("/proc/{}/fd", std::process::id())) {
            n += 1;
            println!("    {}: {}", entry.path().display(), link.display());
        }
    }
    println!("    total: {}", n);

    dump("/proc/self/mounts").await;
}

async fn sleep(seconds: u64) {
    time::sleep(time::Duration::from_secs(seconds)).await;
    println!("Exiting after {} seconds sleep", seconds);
    process::exit(0);
}
