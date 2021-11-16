use super::{Error, RepositoryId};
use crate::common::non_null_string::NonNullString;
use nix::{sys::stat, unistd};
use serde::Deserialize;
use std::{
    collections::HashMap,
    os::unix::prelude::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::fs;
use url::Url;

/// Runtime configuration
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Console address.
    pub console: Option<Vec<Url>>,
    /// Directory with unpacked containers.
    pub run_dir: PathBuf,
    /// Directory where rw data of container shall be stored
    pub data_dir: PathBuf,
    /// Directory for logfile
    pub log_dir: PathBuf,
    /// Top level cgroup name
    pub cgroup: NonNullString,
    /// Max number of parallel mounts
    pub mount_parallel: usize,
    /// Repositories
    pub repositories: HashMap<RepositoryId, Repository>,
    /// Debugging options
    pub debug: Option<Debug>,
}

/// Repository type
#[derive(Clone, Debug, Deserialize)]
pub enum RepositoryType {
    /// Directory based
    #[serde(rename = "fs")]
    Fs {
        /// Path to the repository
        dir: PathBuf,
    },
    /// Memory based
    #[serde(rename = "mem")]
    Memory,
}

/// Repository configuration
#[derive(Clone, Debug, Deserialize)]
pub struct Repository {
    /// Optional key for this repository
    pub key: Option<PathBuf>,
    /// Repository type: fs or mem
    pub r#type: RepositoryType,
}

/// Container debug settings
#[derive(Clone, Debug, Deserialize)]
pub struct Debug {
    /// Strace options
    pub strace: Option<debug::Strace>,
    /// perf options
    pub perf: Option<debug::Perf>,
}

/// Container debug facilities
pub mod debug {
    use serde::Deserialize;
    use std::path::PathBuf;

    /// strace output configuration
    #[derive(Clone, Debug, Deserialize)]
    #[serde(rename_all(deserialize = "snake_case"))]
    pub enum StraceOutput {
        /// Log to a file in log_dir
        File,
        /// Log the runtimes logging system
        Log,
    }

    /// Strace debug options
    #[derive(Clone, Debug, Deserialize)]
    pub struct Strace {
        /// Log to a file in log_dir
        pub output: StraceOutput,
        /// Path to the strace binary
        pub path: Option<PathBuf>,
        /// Additional strace command line flags options
        pub flags: Option<String>,
        /// Include strace output before final execve
        pub include_runtime: Option<bool>,
    }

    /// perf profiling options
    #[derive(Clone, Debug, Deserialize)]
    pub struct Perf {
        /// Path to the perf binary
        pub path: Option<PathBuf>,
        /// Optional additional flags
        pub flags: Option<String>,
    }
}

impl Config {
    /// Validate the configuration
    pub(crate) async fn check(&self) -> Result<(), Error> {
        // Check run_dir for existence and rw
        if !self.run_dir.exists() {
            return Err(Error::Configuration(format!(
                "Configured run_dir {} does not exist",
                self.run_dir.display()
            )));
        } else if !is_rw(&self.run_dir).await {
            return Err(Error::Configuration(format!(
                "Configured run_dir {} is not read and/or writeable",
                self.run_dir.display()
            )));
        }

        // Check data_dir for existence and rw
        if !self.data_dir.exists() {
            return Err(Error::Configuration(format!(
                "Configured data_dir {} does not exist",
                self.data_dir.display()
            )));
        } else if !is_rw(&self.data_dir).await {
            return Err(Error::Configuration(format!(
                "Configured data_dir {} is not read and/or writeable",
                self.data_dir.display()
            )));
        }

        // Check log_dir for existence and rw
        if !self.log_dir.exists() {
            return Err(Error::Configuration(format!(
                "Configured data_dir {} does not exist",
                self.log_dir.display()
            )));
        } else if !is_rw(&self.log_dir).await {
            return Err(Error::Configuration(format!(
                "Configured log_dir {} is not read and/or writeable",
                self.log_dir.display()
            )));
        }

        Ok(())
    }
}

/// Return true if path is read and writeable
async fn is_rw(path: &Path) -> bool {
    match fs::metadata(path).await {
        Ok(stat) => {
            let same_uid = stat.uid() == unistd::getuid().as_raw();
            let same_gid = stat.gid() == unistd::getgid().as_raw();
            let mode = stat::Mode::from_bits_truncate(stat.permissions().mode());

            let is_readable = (same_uid && mode.contains(stat::Mode::S_IRUSR))
                || (same_gid && mode.contains(stat::Mode::S_IRGRP))
                || mode.contains(stat::Mode::S_IROTH);
            let is_writable = (same_uid && mode.contains(stat::Mode::S_IWUSR))
                || (same_gid && mode.contains(stat::Mode::S_IWGRP))
                || mode.contains(stat::Mode::S_IWOTH);

            is_readable && is_writable
        }
        Err(_) => false,
    }
}
