use std::{
    collections::HashMap,
    os::unix::prelude::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time,
};

use anyhow::{bail, Context};
use bytesize::ByteSize;
use nix::{sys::stat, unistd};
use serde::{de::Error as SerdeError, Deserialize, Deserializer};
use url::Url;

use crate::{common::non_nul_string::NonNulString, runtime::repository::RepositoryId};

/// Runtime configuration
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Directory with unpacked containers.
    pub run_dir: PathBuf,
    /// Directory where rw data of container shall be stored
    pub data_dir: PathBuf,
    /// Directory for sockets
    pub socket_dir: PathBuf,
    /// Top level cgroup name
    pub cgroup: NonNulString,
    /// Event loop buffer size
    #[serde(default = "default_event_buffer_size")]
    pub event_buffer_size: usize,
    /// Notification buffer size
    #[serde(default = "default_notification_buffer_size")]
    pub notification_buffer_size: usize,
    /// Loop device timeout
    #[serde(with = "humantime_serde", default = "default_loop_device_timeout")]
    pub loop_device_timeout: time::Duration,
    /// Token validity
    #[serde(with = "humantime_serde", default = "default_token_validity")]
    pub token_validity: time::Duration,
    /// Repositories
    #[serde(default)]
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
#[serde(deny_unknown_fields)]
pub struct Repository {
    /// Repository type: fs or mem.
    pub r#type: RepositoryType,
    /// Optional key for this repository.
    pub key: Option<PathBuf>,
    /// Mount the containers from this repository on runtime start. Default: false.
    #[serde(default)]
    pub mount_on_start: bool,
    /// Maximum number of containers that can be stored in this repository.
    pub capacity_num: Option<u32>,
    /// Maximum total size of all containers in this repository.
    #[serde(default, deserialize_with = "bytesize")]
    pub capacity_size: Option<u64>,
}

/// Container debug settings
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Debug {
    /// Console configuration
    #[serde(deserialize_with = "console")]
    pub console: Url,

    /// Commands to run before the container is started.
    //  <CONTAINER> is replaced with the container name.
    //  <PID> is replaced with the container init pid.
    #[serde(default)]
    pub commands: Vec<String>,
}

impl Config {
    /// Validate the configuration
    pub(crate) fn check(&self) -> anyhow::Result<()> {
        check_rw_directory(&self.run_dir).context("checking run_dir")?;
        check_rw_directory(&self.data_dir).context("checking data_dir")?;
        check_rw_directory(&self.socket_dir).context("checking socket_dir")?;
        Ok(())
    }
}

/// Checks that the directory exists and that it is readable and writeable
fn check_rw_directory(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        bail!("{} does not exist", path.display());
    } else if !is_rw(path) {
        bail!("{} is not read and/or writeable", path.display());
    } else {
        Ok(())
    }
}

/// Return true if path is read and writeable
fn is_rw(path: &Path) -> bool {
    match std::fs::metadata(path) {
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

/// Validate the console url schemes are all "tcp" or "unix"
fn console<'de, D>(deserializer: D) -> Result<Url, D::Error>
where
    D: Deserializer<'de>,
{
    let url = Url::deserialize(deserializer)?;
    if url.scheme() != "tcp" && url.scheme() != "unix" {
        Err(D::Error::custom("console scheme must be tcp or unix"))
    } else {
        Ok(url)
    }
}

/// Parse human readable byte sizes.
fn bytesize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let size: Option<String> = Option::<String>::deserialize(deserializer)?;
    if let Some(size) = size {
        Ok(Some(
            size.parse::<ByteSize>()
                .map_err(D::Error::custom)
                .map(|s| s.as_u64())?,
        ))
    } else {
        Ok(None)
    }
}

const fn default_loop_device_timeout() -> time::Duration {
    time::Duration::from_secs(10)
}

const fn default_event_buffer_size() -> usize {
    256
}

const fn default_notification_buffer_size() -> usize {
    128
}

const fn default_token_validity() -> time::Duration {
    time::Duration::from_secs(60)
}

#[test]
#[allow(clippy::unwrap_used)]
fn console_url() {
    let config = r#"
run_dir = "target/northstar/run"
data_dir = "target/northstar/data"
socket_dir = "target/northstar/sockets"
cgroup = "northstar"

[debug]
console = "tcp://localhost:4200"
"#;

    toml::from_str::<Config>(config).unwrap();

    // Invalid url
    let config = r#"
run_dir = "target/northstar/run"
data_dir = "target/northstar/data"
socket_dir = "target/northstar/sockets"
cgroup = "northstar"

[debug]
console = "http://localhost:4200"
"#;

    assert!(toml::from_str::<Config>(config).is_err());
}

#[test]
#[allow(clippy::unwrap_used)]
fn repository_size() {
    let config = r#"
run_dir = "target/northstar/run"
data_dir = "target/northstar/data"
socket_dir = "target/northstar/sockets"
cgroup = "northstar"

[repositories.memory]
type = "mem"
key = "examples/northstar.pub"
capacity_num = 10
capacity_size = "100MB"
"#;
    toml::from_str::<Config>(config).unwrap();
}
