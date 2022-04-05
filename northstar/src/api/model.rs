use derive_new::new;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Console configuration
pub type Configuration = crate::npk::manifest::Console;
/// Console permission entity
pub type Permission = crate::npk::manifest::ConsolePermission;
/// Container identification
pub type Container = crate::common::container::Container;
/// Container exit code
pub type ExitCode = i32;
/// Manifest
pub type Manifest = crate::npk::manifest::Manifest;
/// String that never contains a null byte
pub type NonNullString = crate::common::non_null_string::NonNullString;
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

/// API version
const VERSION: Version = Version::new(0, 2, 2);

/// API version
pub const fn version() -> Version {
    VERSION
}

/// Message
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Message {
    Connect { connect: Connect },
    Request { request: Request },
    Response { response: Response },
    Notification { notification: Notification },
}

/// Notification / Event
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Notification {
    Started {
        container: Container,
    },
    Exit {
        container: Container,
        status: ExitStatus,
    },
    Install {
        container: Container,
    },
    Uninstall {
        container: Container,
    },
    CGroup {
        container: Container,
        notification: CgroupNotification,
    },
    Shutdown,
}

/// Cgroup event
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum CgroupNotification {
    Memory(MemoryNotification),
}

/// CGroup memory event data
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub struct MemoryNotification {
    pub low: Option<u64>,
    pub high: Option<u64>,
    pub max: Option<u64>,
    pub oom: Option<u64>,
    pub oom_kill: Option<u64>,
}

/// Connect meta information
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Connect {
    Connect {
        /// API version
        version: Version,
        /// Subscribe this connection to notifications
        subscribe_notifications: bool,
    },
    /// Ack
    Ack { configuration: Configuration },
    /// Nack
    Nack {
        /// Nack reason
        error: ConnectNack,
    },
}

/// Connection nack
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum ConnectNack {
    InvalidProtocolVersion { version: Version },
    PermissionDenied,
}

/// Request
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Request {
    /// Runtime shutdown
    Shutdown,
    /// Container list
    Containers,
    /// Repository list
    Repositories,
    /// Start a contianer
    Start {
        /// Container
        container: Container,
        /// Optional command line arguments
        args: Vec<NonNullString>,
        /// Optional environment variables
        env: HashMap<NonNullString, NonNullString>,
    },
    Kill {
        container: Container,
        signal: i32,
    },
    Install {
        repository: RepositoryId,
        size: u64,
    },
    Mount {
        containers: Vec<Container>,
    },
    Umount {
        containers: Vec<Container>,
    },
    Uninstall {
        container: Container,
    },
    ContainerStats {
        container: Container,
    },
}

/// Container information
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ContainerData {
    /// Container name and version
    pub container: Container,
    /// Repository in which the container is installed
    pub repository: RepositoryId,
    /// Container manifest
    pub manifest: Manifest,
    /// Process if the container is started
    pub process: Option<Process>,
    /// Mount state
    pub mounted: bool,
}

/// Process information
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Process {
    /// Process id
    pub pid: Pid,
    /// Process uptime in nanoseconds
    pub uptime: u64,
}

/// Result of a mount operation
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum MountResult {
    Ok { container: Container },
    Error { container: Container, error: Error },
}

/// Result of a umount operation
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum UmountResult {
    Ok { container: Container },
    Error { container: Container, error: Error },
}

/// Response
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Response {
    Ok,
    Containers {
        containers: Vec<ContainerData>,
    },
    Repositories {
        repositories: HashSet<RepositoryId>,
    },
    Mount {
        result: Vec<MountResult>,
    },
    Umount {
        result: Vec<UmountResult>,
    },
    ContainerStats {
        container: Container,
        stats: ContainerStats,
    },
    Error {
        error: Error,
    },
}

/// Container exit status
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
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

/// API error
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Error {
    Configuration {
        context: String,
    },
    PermissionDenied {
        /// Permissions of this connections
        permissions: HashSet<Permission>,
        /// Requred permission
        required: Permission,
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
        resource: Container,
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
        module: String,
        error: String,
    },
}
