use derive_new::new;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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

const VERSION: Version = Version::new(0, 1, 3);

/// Protocol version
/// TODO: Do some static initialization of the version struct
pub fn version() -> Version {
    VERSION
}

/// Container exit status
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum ExitStatus {
    /// Process exited with exit code
    Exit(ExitCode),
    /// Process was terminated by a signal
    Signalled(Signal),
}

/// Message
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Message {
    Connect(Connect),
    Request(Request),
    Response(Response),
    Notification(Notification),
}

/// Notification / Event
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Notification {
    Started(Container),
    Exit(Container, ExitStatus),
    Install(Container),
    Uninstall(Container),
    CGroup(Container, CgroupNotification),
    Shutdown,
}

/// Cgroup event
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum CgroupNotification {
    Memory(MemoryNotification),
}

/// CGroup memory event data
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct MemoryNotification {
    pub low: Option<u64>,
    pub high: Option<u64>,
    pub max: Option<u64>,
    pub oom: Option<u64>,
    pub oom_kill: Option<u64>,
}

/// Connect meta information
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Connect {
    Connect {
        version: Version,
        /// Subscribe this connection to notifications
        subscribe_notifications: bool,
    },
    ConnectAck,
    ConnectNack(ConnectNack),
}

/// Connection nack
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum ConnectNack {
    InvalidProtocolVersion(Version),
}

/// Request
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Request {
    Containers,
    Install(RepositoryId, u64),
    Mount(Vec<Container>),
    Repositories,
    Shutdown,
    Start(
        Container,
        Option<Vec<NonNullString>>, // Optional command line arguments
        Option<HashMap<NonNullString, NonNullString>>, // Optional env variables
    ),
    Kill(Container, i32),
    Umount(Container),
    Uninstall(Container),
    ContainerStats(Container),
}

/// Container information
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
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
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Process {
    /// Process id
    pub pid: Pid,
    /// Process uptime in nanoseconds
    pub uptime: u64,
}

/// Result of a mount operation
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum MountResult {
    Ok(Container),
    Err((Container, Error)),
}

/// Response
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Response {
    Ok(()),
    Containers(Vec<ContainerData>),
    Repositories(HashSet<RepositoryId>),
    Mount(Vec<MountResult>),
    ContainerStats(Container, ContainerStats),
    Err(Error),
}

/// Container statistics
pub type ContainerStats = HashMap<String, serde_json::Value>;

/// API error
#[derive(new, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Error {
    Configuration(String),
    DuplicateContainer(Container),
    InvalidContainer(Container),
    InvalidArguments(String),
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
    Seccomp(String),
    Name(String),
    Key(String),

    Unexpected(String, String),
}
