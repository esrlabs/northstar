use anyhow::{Context, Result};
use clap::Parser;
use nix::{
    libc,
    unistd::{self, Gid},
};
use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    ptr::null_mut,
    str::FromStr,
    thread, time,
};
use thiserror::Error;

/// Northstar test container
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Opt {
    #[clap(subcommand)]
    command: Option<Command>,
}

#[derive(Debug)]
enum Io {
    Stdout,
    Stderr,
}

#[derive(Error, Debug)]
enum Error {
    #[error("invalid io: {0}")]
    ParseError(String),
}

impl FromStr for Io {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "stdout" => Ok(Io::Stdout),
            "stderr" => Ok(Io::Stderr),
            _ => Err(Error::ParseError(s.to_string())),
        }
    }
}

#[derive(Debug, Parser)]
enum Command {
    Cat {
        #[clap(value_parser)]
        path: PathBuf,
    },
    Crash,
    Exit {
        code: i32,
    },
    Inspect,
    Print {
        message: String,
        #[clap(short, long, default_value = "stdout")]
        io: Io,
    },
    Touch {
        path: PathBuf,
    },
    Sleep,
    Write {
        message: String,
        path: PathBuf,
    },
    CallDeleteModule {
        flags: String,
    },
}

fn main() -> Result<()> {
    let command = Opt::parse().command.unwrap_or(Command::Sleep);
    println!("Executing \"{:?}\"", command);
    match command {
        Command::CallDeleteModule { flags } => call_delete_module(flags)?,
        Command::Cat { path } => cat(&path)?,
        Command::Crash => crash(),
        Command::Exit { code } => exit(code),
        Command::Inspect => inspect(),
        Command::Print { message, io } => print(&message, &io),
        Command::Sleep => (),
        Command::Touch { path } => touch(&path)?,
        Command::Write { message, path } => write(&message, path.as_path())?,
    };

    sleep();

    Ok(())
}

fn sleep() {
    println!("Sleeping...");
    thread::sleep(time::Duration::from_secs(u64::MAX));
}

fn dump(file: &str) {
    println!("{}:", file);
    fs::read_to_string(file)
        .unwrap_or_else(|_| panic!("dump {}", file))
        .lines()
        .for_each(|l| println!("  {}", l));
}

fn cat(path: &Path) -> Result<()> {
    let mut input =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut output = std::io::stdout();
    io::copy(&mut input, &mut output)
        .map(drop)
        .with_context(|| format!("failed to cat {}", path.display()))?;
    writeln!(output).context("failed to write to stdout")
}

fn crash() {
    panic!("witness me!");
}

fn print(message: &str, io: &Io) {
    match io {
        Io::Stdout => println!("{}", message),
        Io::Stderr => eprintln!("{}", message),
    }
}

fn exit(code: i32) {
    std::process::exit(code);
}

fn write(input: &str, path: &Path) -> Result<()> {
    fs::write(path, input)
        .with_context(|| format!("failed to write \"{}\" to {}", input, path.display()))
}

fn touch(path: &Path) -> Result<()> {
    fs::File::create(path)?;
    Ok(())
}

/// Call the 'delete_module' syscall with an empty module name. This has no effect and just returns -1.
/// Since the call is not allowed by the default seccomp profile it is used to test seccomp.
fn call_delete_module(option: String) -> Result<()> {
    let option = option.parse::<u32>().unwrap();
    let result = unsafe { libc::syscall(libc::SYS_delete_module, null_mut::<u32>(), option) };
    println!("delete_module syscall was successful ({})", result);
    Ok(())
}

fn inspect() {
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
            caps::read(None, *set).expect("failed to read caps")
        );
    }

    println!("/proc/self/fd:");
    fs::read_dir("/proc/self/fd")
        .expect("read_dir /proc/self/fd")
        .map(|e| e.unwrap().path())
        .map(|p| (p.clone(), fs::read_link(p).expect("readlink entry")))
        .filter(|(_, l)| l != &PathBuf::from(format!("/proc/{}/fd", std::process::id())))
        .for_each(|(p, l)| {
            println!("    {}: {}", p.display(), l.display());
        });
    // Substract the ReadDir fd
    println!(
        "    total: {}",
        fs::read_dir("/proc/self/fd").unwrap().count() - 1
    );

    dump("/proc/self/mounts");
    dump("/proc/self/limits");
}
