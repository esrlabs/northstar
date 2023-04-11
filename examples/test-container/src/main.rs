use anyhow::{anyhow, Context, Error, Result};
use clap::Parser;
use nix::libc;
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    ptr::null_mut,
    str::FromStr,
    thread,
};

mod inspect;
mod sockets;

/// Northstar test container
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opt {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Clone)]
enum Io {
    Stdout,
    Stderr,
}

impl FromStr for Io {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "stdout" => Ok(Io::Stdout),
            "stderr" => Ok(Io::Stderr),
            _ => Err(anyhow!("failed to parse")),
        }
    }
}

#[derive(Debug, Parser)]
enum Command {
    CallDeleteModule {
        flags: u32,
    },
    Cat {
        #[arg()]
        path: PathBuf,
    },
    Crash,
    Exit {
        code: i32,
    },
    Inspect,
    Print {
        message: String,
        #[arg(short, long, default_value = "stdout")]
        io: Io,
    },
    Sleep,
    Socket {
        socket: String,
    },
    Touch {
        path: PathBuf,
    },
    Write {
        message: String,
        path: PathBuf,
    },
}

fn main() -> Result<()> {
    let command = Opt::parse().command.unwrap_or(Command::Sleep);
    println!("Executing \"{command:?}\"");
    match command {
        Command::CallDeleteModule { flags } => call_delete_module(flags)?,
        Command::Cat { path } => cat(&path)?,
        Command::Crash => crash(),
        Command::Socket { socket } => sockets::run(&socket)?,
        Command::Exit { code } => exit(code),
        Command::Inspect => inspect::run(),
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
    thread::park();
}

fn dump(file: &Path) {
    println!("{file:?}");
    fs::File::open(file)
        .and_then(|mut file| io::copy(&mut file, &mut io::stdout()))
        .unwrap_or_else(|_| panic!("dump {}", file.display()));
}

fn cat(path: &Path) -> Result<()> {
    let mut input =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut output = io::stdout();
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
        Io::Stdout => println!("{message}"),
        Io::Stderr => eprintln!("{message}"),
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
    fs::File::create(path).map(drop).map_err(Into::into)
}

/// Call the 'delete_module' syscall with an empty module name. This has no effect and just returns -1.
/// Since the call is not allowed by the default seccomp profile it is used to test seccomp.
fn call_delete_module(option: u32) -> Result<()> {
    let result = unsafe { libc::syscall(libc::SYS_delete_module, null_mut::<u32>(), option) };
    println!("delete_module syscall was successful ({result})");
    Ok(())
}
