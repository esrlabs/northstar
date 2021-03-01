// Copyright (c) 2019 - 2020 ESRLabs.
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

use log::Level;
use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf};
use url::Url;

use super::RepositoryId;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Log level: DEBUG, INFO, WARN or ERROR
    pub log_level: Level,
    /// Console address.
    pub console: Option<Url>,
    /// Directory with unpacked containers.
    pub run_dir: PathBuf,
    /// Directory where rw data of container shall be stored
    pub data_dir: PathBuf,
    /// Directory for logfile
    pub log_dir: PathBuf,

    pub repositories: HashMap<RepositoryId, Repository>,
    pub cgroups: CGroups,
    pub devices: Devices,

    /// Debugging options
    pub debug: Option<Debug>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Repository {
    /// Directory containing images in container format
    pub dir: PathBuf,
    /// Directory where public signing keys are stored
    pub key: Option<PathBuf>,
}

/// This map specifies the root cgroup under which the application cgroups are inserted.
/// The directory is created if it does not exist.
/// If not set for a specific cgroup, it defaults to "north".
pub type CGroups = HashMap<String, PathBuf>;

#[derive(Clone, Debug, Deserialize)]
pub struct Devices {
    /// Parent mountpoint of northstar path. Northstar needs to set private mount propagation
    /// on the parent mount of the northstar runtime dir. This mountpoint varies.
    pub unshare_root: PathBuf,
    /// Device mapper control file e.g /dev/mapper/control
    pub device_mapper: PathBuf,
    /// Device mapper dev prefix e.g /dev/mapper/dm-
    pub device_mapper_dev: String,
    /// Loopback control file e.g /dev/loop-control
    pub loop_control: PathBuf,
    /// Loopback device files e.g /dev/loop or /dev/block/loop
    pub loop_dev: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Debug {
    /// Runtime debug options
    pub runtime: Option<debug::Runtime>,
    /// Strace options
    pub strace: Option<debug::Strace>,
    /// perf options
    pub perf: Option<debug::Perf>,
}

pub mod debug {
    use serde::Deserialize;
    use std::path::PathBuf;

    /// Runtime debug options
    #[derive(Clone, Debug, Deserialize)]
    pub struct Runtime {
        /// Do not enter a mount namespace if this option is set
        /// This exposes the `run_dir` mounts for debugging. Be aware
        /// that in case of a non normal termination of the runtime the
        /// images mounted in `run_dir` have to be umounted manually before
        /// starting the runtime again.
        pub disable_mount_namespace: bool,
    }

    #[derive(Clone, Debug, Deserialize)]
    pub enum StraceOutput {
        /// Log to a file in log_dir
        #[serde(rename = "file")]
        File,
        /// Log the runtimes logging system
        #[serde(rename = "log")]
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
