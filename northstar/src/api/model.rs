// Copyright (c) 2020 ESRLabs
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

use derive_new::new;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub type Container = crate::common::container::Container;
pub type ContainerError = crate::common::container::Error;
pub type ExitCode = i32;
pub type Manifest = crate::npk::manifest::Manifest;
pub type Profile = crate::npk::manifest::Profile;
pub type Version = crate::common::version::Version;
pub type Pid = u32;
pub type RepositoryId = String;
pub type Signal = u32;

const VERSION: Version = Version {
    major: 0,
    minor: 0,
    patch: 6,
    pre: vec![],
    build: vec![],
};

/// Protocol version
/// TODO: Do some static initialization of the version struct
pub fn version() -> Version {
    VERSION
}

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum ExitStatus {
    /// Process exited with exit code
    Exit(ExitCode),
    /// Process was terminated by a signal
    Signaled(Signal),
}

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Message {
    Connect(Connect),
    Request(Request),
    Response(Response),
    Notification(Notification),
}

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Notification {
    OutOfMemory(Container),
    Exit(Container, ExitStatus),
    Install(Container),
    Uninstall(Container),
    Started(Container),
    Stopped(Container, ExitStatus),
    Shutdown,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Connect {
    Connect {
        version: Version,
        /// Subscribe this connection to notifications
        subscribe_notifications: bool,
    },
    ConnectAck,
    ConnectNack(ConnectNack),
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum ConnectNack {
    InvalidProtocolVersion(Version),
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Request {
    Containers,
    Install(RepositoryId, u64),
    Mount(Vec<Container>),
    Repositories,
    Shutdown,
    Start(Container),
    /// Stop the given container. If the process does not exit within
    /// the timeout in seconds it is SIGKILLED
    Stop(Container, u64),
    Umount(Container),
    Uninstall(Container),
}

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct ContainerData {
    pub container: Container,
    pub repository: RepositoryId,
    pub manifest: Manifest,
    pub process: Option<Process>,
    pub mounted: bool,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Process {
    /// Process id
    pub pid: Pid,
    /// Process uptime in nanoseconds
    pub uptime: u64,
    /// Resources used and allocated by this process
    pub resources: Resources,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Resources {
    /// Memory resources used by process
    pub memory: Option<Memory>,
}

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Memory {
    pub size: u64,
    pub resident: u64,
    pub shared: u64,
    pub text: u64,
    pub data: u64,
}

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum MountResult {
    Ok(Container),
    Err((Container, Error)),
}

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Response {
    Ok(()),
    Containers(Vec<ContainerData>),
    Repositories(HashSet<RepositoryId>),
    Mount(Vec<MountResult>),
    Err(Error),
}

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Error {
    Configuration(String),
    DuplicateContainer(Container),
    InvalidContainer(Container),
    MountBusy(Container),
    UmountBusy(Container),
    StartContainerStarted(Container),
    StartContainerResource(Container),
    StartContainerMissingResource(Container, Container),
    StartContainerFailed(Container, String),
    StopContainerNotStarted(Container),
    InvalidRepository(RepositoryId),
    InstallDuplicate(Container),
    CriticalContainer(Container, ExitStatus),

    Npk(String, String),
    Process(String),
    Console(String),
    Cgroups(String),
    Mount(String),
    Name(String),
    Key(String),

    Io(String),
    Os(String),
}
