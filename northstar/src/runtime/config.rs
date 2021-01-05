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

use npk::archive::RepositoryId;
use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf};

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
    /// Filesystem type of the fs mounted on `unshare_root`
    pub unshare_fstype: String,
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
pub struct Bridge {
    /// If any container uses network namespaces, the IPv4 address of
    /// the bridge must be specified.
    pub enabled: bool,
    /// IPv4 address must be a /16 address; each namespace is assigned
    /// a fixed addr within the subnet specified in the manifest
    /// along with a separate addr for a VM within the subnet
    pub ipv4_slash16: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Print debug logs.
    pub debug: bool,
    /// Console address.
    pub console_address: String,
    /// Container UID
    pub container_uid: u32,
    /// Container GID
    pub container_gid: u32,
    /// Directory with unpacked containers.
    pub run_dir: PathBuf,
    /// Directory where rw data of container shall be stored
    pub data_dir: PathBuf,

    pub repositories: HashMap<RepositoryId, Repository>,
    pub cgroups: CGroups,
    pub devices: Devices,
    pub bridge: Bridge,
}
