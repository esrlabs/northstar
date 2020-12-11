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

use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf};

pub type RepositoryId = String;

#[derive(Clone, Debug, Deserialize)]
pub struct Repository {
    /// Directory containing images in container format
    pub dir: PathBuf,
    /// Directory where public signing keys are stored
    pub key: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CGroups {
    /// CGroups Memory dir. This is the subdir added to the root memory cgroup.
    /// The directory is created if it does not exist.
    /// This groups acts as the toplevel north memory cgroup.
    pub memory: PathBuf,

    /// CGroups CPU dir. This is the subdir added to the root cpu cgroup.
    /// The directory is created if it does not exist.
    /// This groups acts as the toplevel north cpu cgroup.
    pub cpu: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Devices {
    /// Parent mountpoint of north path. North needs to set private mount propagation
    /// on the parent mount of the north runtime dir. This mountpoint varies.
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
}
