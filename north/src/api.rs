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

use npk::manifest::{Manifest, Version};

pub type Name = String;
pub type MessageId = String; // UUID

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
    OutOfMemory(Name),
    ApplicationExited {
        id: Name,
        version: Version,
        exit_info: String,
    },
    Install(Name, Version),
    Uninstalled(Name, Version),
    ApplicationStarted(Name, Version),
    ApplicationStopped(Name, Version),
    Shutdown,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Request {
    Containers,
    Start(Name),
    Stop(Name),
    Install(u64),
    Uninstall { name: Name, version: Version },
    Shutdown,
}

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Container {
    pub manifest: Manifest,
    pub process: Option<Process>,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    pub uptime: u64,
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
pub enum Response {
    Ok(()),
    Containers(Vec<Container>),
    Err(Error),
}

#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Error {
    ApplicationNotFound,
    ApplicationNotRunning,
    ApplicationRunning(String),
    MissingResource(String),
    ApplicationAlreadyInstalled(String),
    ResourceAlreadyInstalled(String),

    Npk(String),
    Process(String),
    Console(String),
    Cgroups(String),
    Mount(String),
    Key(String),

    Io(String),
    Os(String),
}
