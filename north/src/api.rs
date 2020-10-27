use serde::{Deserialize, Serialize};

use crate::manifest::{Manifest, Version};

pub type Name = String;
pub type MessageId = String; // UUID

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: MessageId, // used to match response with a request
    pub payload: Payload,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Payload {
    Request(Request),
    Response(Response),
    Installation(usize), // size of npk that will be sent
    Notification(Notification),
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Notification {
    OutOfMemory(Name),
    InstallationFinished(Name),
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Request {
    Containers,
    Start(Name),
    Stop(Name),
    Uninstall { name: Name, version: Version },
    Shutdown,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Memory {
    pub size: u64,
    pub resident: u64,
    pub shared: u64,
    pub text: u64,
    pub data: u64,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Response {
    Containers(Vec<Container>),
    Start { result: StartResult },
    Stop { result: StopResult },
    Uninstall { result: UninstallResult },
    Install { result: InstallationResult },
    Shutdown { result: ShutdownResult },
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum StartResult {
    Success,
    Error(String),
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum StopResult {
    Success,
    Error(String), // TODO
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum UninstallResult {
    Success,
    Error(String), // TODO
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum InstallationResult {
    Success,
    ApplicationAlreadyInstalled,
    DuplicateResource,
    FileCorrupted,
    SignatureNotFound,
    InvalidSignatureYaml,
    MalformedSignature,
    MalformedHashes,
    MalformedManifest(String),
    VerityProblem(String),
    ArchiveError(String),
    DeviceMapperProblem(String),
    LoopDeviceError(String),
    HashInvalid(String),
    KeyNotFound(String),
    InternalError(String),
    MountError(String),
    NoVerityHeader,
    UnexpectedVerityAlgorithm(String),
    UnexpectedVerityVersion(u32),
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum ShutdownResult {
    Success,
    Error(String), // TODO
}
