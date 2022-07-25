use northstar_runtime::common::non_nul_string::NonNulString;
use std::{
    collections::HashMap,
    fs,
    io::{self, BufRead},
    path::PathBuf,
};

use anyhow::{Context, Result};
use northstar_runtime::seccomp::{profiles::default::SYSCALLS_BASE, Profile, Seccomp, SyscallRule};

pub fn seccomp(path: PathBuf, no_default_profile: bool) -> Result<()> {
    // Collect syscall names from strace file
    let file =
        fs::File::open(&path).context(format!("failed to open strace log: {}", &path.display()))?;
    let mut syscalls: HashMap<NonNulString, SyscallRule> = HashMap::new();
    // unwrap(): Creating regex from constant expression will never fail
    let regex = regex::Regex::new(r"^\s*(?:\[[^]]*]|\d+)?\s*([a-zA-Z0-9_]+)\(([^)<]*)").unwrap();
    io::BufReader::new(file)
        .lines()
        .try_for_each(|line| -> Result<()> {
            if let Some(caps) = regex.captures(line?.as_str()) {
                if let Some(m) = caps.get(1) {
                    if no_default_profile || !SYSCALLS_BASE.contains(&m.as_str()) {
                        syscalls.insert(NonNulString::try_from(m.as_str())?, SyscallRule::Any);
                    }
                }
            }
            Ok(())
        })?;

    let profile = (!no_default_profile).then(|| Profile::Default);
    let allow = (!syscalls.is_empty()).then(|| syscalls);

    println!("{}", &serde_yaml::to_string(&Seccomp { profile, allow })?);
    Ok(())
}
