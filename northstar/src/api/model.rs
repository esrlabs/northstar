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
use npk::manifest::{Manifest, Version};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};

pub type Name = String;
pub type RepositoryId = String;
pub type MessageId = String; // UUID
pub type Container = super::container::Container;

const VERSION: &str = "0.0.2";

pub fn version() -> Version {
    Version::parse(VERSION).unwrap()
}

pub type ExitCode = i32;
pub type Signal = u32;

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum ExitStatus {
    /// Process exited with exit code
    Exit(ExitCode),
    /// Process was terminated by a signal
    Signaled(Signal),
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: MessageId, // used to match response with a request
    pub payload: Payload,
}

impl Message {
    pub fn new(payload: Payload) -> Message {
        Message {
            id: uuid::Uuid::new_v4().to_string(),
            payload,
        }
    }

    pub fn new_request(request: Request) -> Message {
        Message::new(Payload::Request(request))
    }

    pub fn new_response(respone: Response) -> Message {
        Message::new(Payload::Response(respone))
    }

    pub fn new_notification(notification: Notification) -> Message {
        Message::new(Payload::Notification(notification))
    }
}

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Payload {
    Request(Request),
    Response(Response),
    Notification(Notification),
}

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Notification {
    OutOfMemory(Container),
    Exit {
        container: Container,
        status: ExitStatus,
    },
    Install(Name, Version),
    Uninstalled(Name, Version),
    Started(Container),
    Stopped(Container),
    Shutdown,
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

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Repository {
    pub dir: PathBuf,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Process {
    /// Process id
    pub pid: u32,
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
    Ok,
    Err(Error),
}

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Response {
    Ok(()),
    Containers(Vec<ContainerData>),
    Repositories(HashMap<RepositoryId, Repository>),
    Mount(Vec<(Container, MountResult)>),
    Err(Error),
}

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Error {
    InvalidContainer(Container),
    UmountBusy(Container),
    StartContainerStarted(Container),
    StartContainerResource(Container),
    StartContainerMissingResource(Container, Container),
    StopContainerNotStarted(Container),
    InvalidRepository(RepositoryId),
    InstallDuplicate(Container),

    Npk(String),
    NpkArchive(String),
    Process(String),
    Console(String),
    Cgroups(String),
    Mount(String),
    Key(String),

    Io(String),
    Os(String),
}
