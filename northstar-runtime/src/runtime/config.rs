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
    /// Console configuration.
    #[serde(default)]
    pub console: Console,
    /// Loop device timeout
    #[serde(with = "humantime_serde", default = "default_loop_device_timeout")]
    pub loop_device_timeout: time::Duration,
    /// Repositories
    #[serde(default)]
    pub repositories: HashMap<RepositoryId, Repository>,
    /// Debugging options
    pub debug: Option<Debug>,
}

/// Console Quality of Service
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Console {
    /// Token validity duration.
    #[serde(with = "humantime_serde", default = "default_token_validity")]
    pub token_validity: time::Duration,
    /// Limits the number of requests processed per second.
    #[serde(default = "default_max_requests_per_second")]
    pub max_requests_per_sec: usize,
    /// Maximum request size in bytes
    #[serde(deserialize_with = "bytesize", default = "default_max_request_size")]
    pub max_request_size: u64,
    /// Maximum npk size in bytes.
    #[serde(
        deserialize_with = "bytesize",
        default = "default_max_npk_install_size"
    )]
    pub max_npk_install_size: u64,
    /// NPK stream timeout in seconds.
    #[serde(with = "humantime_serde", default = "default_npk_stream_timeout")]
    pub npk_stream_timeout: time::Duration,
}

impl Default for Console {
    fn default() -> Self {
        Self {
            token_validity: default_token_validity(),
            max_requests_per_sec: default_max_requests_per_second(),
            max_request_size: default_max_request_size(),
            max_npk_install_size: default_max_npk_install_size(),
            npk_stream_timeout: default_npk_stream_timeout(),
        }
    }
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
fn bytesize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: From<u64>,
{
    String::deserialize(deserializer)
        .and_then(|s| s.parse::<ByteSize>().map_err(D::Error::custom))
        .map(|s| s.as_u64().into())
}

/// Default loop device timeout.
const fn default_loop_device_timeout() -> time::Duration {
    time::Duration::from_secs(10)
}

/// Default event buffer size.
const fn default_event_buffer_size() -> usize {
    256
}

/// Default notification buffer size.
const fn default_notification_buffer_size() -> usize {
    128
}

/// Default token validity time.
const fn default_token_validity() -> time::Duration {
    time::Duration::from_secs(60)
}

/// Default maximum requests per second.
const fn default_max_requests_per_second() -> usize {
    1000
}

/// Default maximum NPK size.
const fn default_max_npk_install_size() -> u64 {
    256 * 1024 * 1024
}
/// Default timeout between two npks stream chunks.
const fn default_npk_stream_timeout() -> time::Duration {
    time::Duration::from_secs(10)
}

/// Default maximum length per request in bytes.
const fn default_max_request_size() -> u64 {
    1024 * 1024
}

#[test]
#[allow(clippy::unwrap_used)]
fn console_url() {
    let config = r#"
data_dir = "target/northstar/data"
run_dir = "target/northstar/run"
socket_dir = "target/northstar/sockets"
cgroup = "northstar"

[debug]
console = "tcp://localhost:4200"
"#;

    toml::from_str::<Config>(config).unwrap();

    // Invalid url
    let config = r#"
data_dir = "target/northstar/data"
run_dir = "target/northstar/run"
socket_dir = "target/northstar/sockets"
cgroup = "northstar"

[debug]
console = "http://localhost:4200"
"#;

    assert!(toml::from_str::<Config>(config).is_err());
}

#[test]
fn repository_size() {
    let config = r#"
data_dir = "target/northstar/data"
run_dir = "target/northstar/run"
socket_dir = "target/northstar/sockets"
cgroup = "northstar"

[repositories.memory]
type = "mem"
key = "examples/northstar.pub"
capacity_num = 10
capacity_size = "100MB"
"#;
    let config = toml::from_str::<Config>(config).expect("failed to parse config");
    let memory = config
        .repositories
        .get("memory")
        .expect("failed to find memory repository");
    assert_eq!(memory.key, Some("examples/northstar.pub".into()));
    assert_eq!(memory.capacity_num, Some(10));
    assert_eq!(memory.capacity_size, Some(100000000));
}
