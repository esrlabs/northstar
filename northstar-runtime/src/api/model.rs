use serde::{Deserialize, Serialize, Serializer};
use std::collections::{HashMap, HashSet};

/// Container name
pub type Name = crate::common::name::Name;
/// Console configuration
pub type ConsoleConfiguration = crate::npk::manifest::console::Configuration;
/// Console permission entity
pub type ConsolePermission = crate::npk::manifest::console::Permission;
/// Container identification
pub type Container = crate::common::container::Container;
/// Container exit code
pub type ExitCode = i32;
/// Manifest
pub type Manifest = crate::npk::manifest::Manifest;
/// String that never contains a null byte
pub type NonNulString = crate::common::non_nul_string::NonNulString;
/// Process id
pub type Pid = u32;
/// Repository id
pub type RepositoryId = String;
/// Unix signal
pub type Signal = u32;
/// Version
pub type Version = crate::common::version::Version;
/// Container statistics
pub type ContainerStats = HashMap<String, serde_json::Value>;

/// Message
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
#[serde(untagged)]
pub enum Message {
    Connect { connect: Connect },
    ConnectAck { connect_ack: ConnectAck },
    ConnectNack { connect_nack: ConnectNack },
    Request { request: Request },
    Response { response: Response },
    Notification { notification: Notification },
}

/// Notification / Event
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Notification {
    CGroup(Container, CgroupNotification),
    Exit(Container, ExitStatus),
    Install(Container),
    Shutdown,
    Started(Container),
    Uninstall(Container),
}

/// Cgroup event
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum CgroupNotification {
    Memory(MemoryNotification),
}

/// CGroup memory event data
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub struct MemoryNotification {
    pub low: Option<u64>,
    pub high: Option<u64>,
    pub max: Option<u64>,
    pub oom: Option<u64>,
    pub oom_kill: Option<u64>,
}

/// Connect
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub struct Connect {
    /// API version
    pub version: Version,
    /// Subscribe this connection to notifications
    pub subscribe_notifications: bool,
}

/// Connection ack
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub struct ConnectAck {
    pub configuration: ConsoleConfiguration,
}

/// Connection nack
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum ConnectNack {
    InvalidProtocolVersion { version: Version },
    PermissionDenied,
}

/// Request
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Request {
    Inspect {
        container: Container,
    },
    Ident,
    Install {
        repository: RepositoryId,
        size: u64,
    },
    Kill {
        container: Container,
        signal: i32,
    },
    List,
    Mount {
        containers: Vec<Container>,
    },
    Repositories,
    Shutdown,
    Start {
        container: Container,
        arguments: Vec<NonNulString>,
        environment: HashMap<NonNulString, NonNulString>,
    },
    TokenCreate {
        target: Name,
        #[serde(with = "base64")]
        shared: Vec<u8>,
    },
    TokenVerify {
        token: Token,
        user: Name,
        #[serde(with = "base64")]
        shared: Vec<u8>,
    },
    Umount {
        containers: Vec<Container>,
    },
    Uninstall {
        container: Container,
        wipe: bool,
    },
}

/// Token
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Token(Vec<u8>);

impl AsRef<[u8]> for Token {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Token {
    fn from(value: Vec<u8>) -> Self {
        Token(value)
    }
}

/// Token verification result
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationResult {
    /// Verification succeeded
    Ok,
    /// Verification failed
    Invalid,
    /// Token is expired
    Expired,
    /// Token time is in the future
    Future,
}

/// Container information
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ContainerData {
    /// Container manifest
    pub manifest: Manifest,
    /// Repository in which the container is installed
    pub repository: RepositoryId,
    /// Mount state
    pub mounted: bool,
    /// Process if the container is started
    pub process: Option<Process>,
}

/// Process information
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Process {
    /// Process id
    pub pid: Pid,
    /// Process uptime in nanoseconds
    pub uptime: u64,
    /// Container statistics
    pub statistics: ContainerStats,
}

/// Mount result
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum MountResult {
    Ok { container: Container },
    Error { container: Container, error: Error },
}

/// Unmount result
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum UmountResult {
    Ok { container: Container },
    Error { container: Container, error: Error },
}

/// Start result
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum StartResult {
    Ok { container: Container },
    Error { container: Container, error: Error },
}

/// Kill result
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum KillResult {
    Ok { container: Container },
    Error { container: Container, error: Error },
}

/// Installation result
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum InstallResult {
    Ok { container: Container },
    Error { error: Error },
}

/// Uninstallation result
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum UninstallResult {
    Ok { container: Container },
    Error { container: Container, error: Error },
}

/// Inspect result
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum InspectResult {
    Ok {
        container: Container,
        data: Box<ContainerData>,
    },
    Error {
        container: Container,
        error: Error,
    },
}

/// Response
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Response {
    Ident(Container),
    Inspect(InspectResult),
    Install(InstallResult),
    Kill(KillResult),
    List(Vec<Container>),
    Mount(Vec<MountResult>),
    PermissionDenied(Request),
    Repositories(HashSet<RepositoryId>),
    Shutdown,
    Start(StartResult),
    Token(Token),
    TokenVerification(VerificationResult),
    Umount(Vec<UmountResult>),
    Uninstall(UninstallResult),
}

/// Container exit status
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitStatus {
    /// Process exited with exit code
    Exit {
        /// Exit code
        code: ExitCode,
    },
    /// Process was terminated by a signal
    Signalled {
        /// Signal
        signal: Signal,
    },
}

impl ExitStatus {
    /// Exit success
    pub const SUCCESS: ExitCode = 0;

    /// Was termination successful? Signal termination is not considered a success,
    /// and success is defined as a zero exit status.
    pub fn success(&self) -> bool {
        matches!(self, ExitStatus::Exit { code } if *code == Self::SUCCESS)
    }

    /// Returns the exit code of the process, if any.
    pub fn code(&self) -> Option<ExitCode> {
        match self {
            ExitStatus::Exit { code } => Some(*code),
            ExitStatus::Signalled { .. } => None,
        }
    }
}

impl std::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitStatus::Exit { code } => write!(f, "Exit({code})"),
            ExitStatus::Signalled { signal } => write!(f, "Signalled({signal})"),
        }
    }
}

/// API error
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Error {
    Configuration {
        context: String,
    },
    DuplicateContainer {
        container: Container,
    },
    InvalidContainer {
        container: Container,
    },
    InvalidArguments {
        cause: String,
    },
    MountBusy {
        container: Container,
    },
    UmountBusy {
        container: Container,
    },
    StartContainerStarted {
        container: Container,
    },
    StartContainerResource {
        container: Container,
    },
    StartContainerMissingResource {
        container: Container,
        resource: Name,
        version: String,
    },
    StartContainerFailed {
        container: Container,
        error: String,
    },
    StopContainerNotStarted {
        container: Container,
    },
    InvalidRepository {
        repository: RepositoryId,
    },
    InstallDuplicate {
        container: Container,
    },
    CriticalContainer {
        container: Container,
        status: ExitStatus,
    },
    Unexpected {
        error: String,
    },
}

impl Serialize for Token {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.0.len() == 40 {
            base64::serialize(&self.0, serializer)
        } else {
            Err(serde::ser::Error::custom("invalid length"))
        }
    }
}

impl<'de> Deserialize<'de> for Token {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let token = base64::deserialize(deserializer)?;
        if token.len() == 40 {
            Ok(Token(token))
        } else {
            Err(serde::de::Error::custom("invalid length"))
        }
    }
}

mod base64 {
    use base64::{engine::general_purpose::STANDARD as Base64, Engine as _};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = Base64.encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        Base64
            .decode(base64.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
