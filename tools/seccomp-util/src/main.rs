use anyhow::{Context, Result};
use clap::Parser;
use northstar::{
    common::non_null_string::NonNullString,
    seccomp::{profiles::default::SYSCALLS_BASE, Profile, Seccomp, SyscallRule},
};
use regex::Regex;
use std::{collections::HashMap, convert::TryFrom, fs::File, io, io::BufRead, path::PathBuf};

#[derive(Debug, Parser)]
struct Opt {
    /// Path to strace log file
    input: PathBuf,
    /// Whether or not to allow the syscalls defined by the default profile
    #[clap(long)]
    no_default_profile: bool,
}

fn main() -> Result<()> {
    env_logger::init();
    let path: PathBuf = Opt::parse().input;
    let no_default_profile = Opt::parse().no_default_profile;

    // Collect syscall names from strace file
    let file =
        File::open(&path).context(format!("Failed to open strace log: {}", &path.display()))?;
    let mut syscalls: HashMap<NonNullString, SyscallRule> = HashMap::new();
    // unwrap(): Creating regex from constant expression will never fail
    let regex = Regex::new(r"^\s*(?:\[[^]]*]|\d+)?\s*([a-zA-Z0-9_]+)\(([^)<]*)").unwrap();
    io::BufReader::new(file)
        .lines()
        .try_for_each(|line| -> Result<()> {
            if let Some(caps) = regex.captures(line?.as_str()) {
                if let Some(m) = caps.get(1) {
                    if no_default_profile || !SYSCALLS_BASE.contains(&m.as_str()) {
                        syscalls.insert(NonNullString::try_from(m.as_str())?, SyscallRule::Any);
                    }
                }
            }
            Ok(())
        })?;

    // Write manifest entry to stdout
    let profile = if no_default_profile {
        None
    } else {
        Some(Profile::Default)
    };
    let allow = if syscalls.is_empty() {
        None
    } else {
        Some(syscalls)
    };
    println!("{}", &serde_yaml::to_string(&Seccomp { profile, allow })?);
    Ok(())
}
