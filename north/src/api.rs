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
    ApplicationExited {
        id: Name,
        version: Version,
        exit_info: String,
    },
    InstallationFinished(Name, Version),
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

/// A lot can go wrong when trying to install an NPK
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum InstallationResult {
    /// Everything went smooth
    Success,
    /// Cannot install an already installed application (only 1 version can be installed)
    ApplicationAlreadyInstalled,
    /// Cannot install the same version a resource container (multiple versions permitted)
    DuplicateResource,
    /// The npk file seems to be corrupted
    FileCorrupted,
    /// The signature file in the npk is invalid
    SignatureFileInvalid,
    /// The signature file in the npk contains malformed signatures
    MalformedSignature,
    /// Signature check failed
    SignatureVerificationFailed(String),
    /// The hashes in the npk file could not be read
    MalformedHashes,
    /// There was a problem reading the manifest in the npk package
    MalformedManifest(String),
    /// Problem with the verity device
    VerityProblem(String),
    /// npk archive seems to be incorrecxt
    ArchiveError(String),
    /// Problems with the device mapper
    DeviceMapperProblem(String),
    /// Problems with the loopback device
    LoopDeviceError(String),
    /// cryptographic hash check failed
    HashInvalid(String),
    /// keyfile seems to be missing
    KeyNotFound(String),
    /// Some problem with managing files
    FileIoProblem(String),
    /// Mount or Un-mount problem
    MountError(String),
    /// A timeout occurred
    TimeoutError(String),
    /// Problems with Inotify
    INotifyError(String),
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum ShutdownResult {
    Success,
    Error(String), // TODO
}
