use schemars::{
    gen::SchemaGenerator,
    schema::{InstanceType, SchemaObject},
    JsonSchema,
};
use serde::{de::Visitor, Deserialize, Serialize, Serializer};
use std::{
    collections::{HashMap, HashSet},
    fmt,
};

/// Console configuration
pub type ConsoleConfiguration = crate::npk::manifest::ConsoleConfiguration;
/// Console permission entity
pub type ConsolePermission = crate::npk::manifest::Permission;
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

/// API version
const VERSION: Version = Version::new(0, 3, 0);

/// API version
pub const fn version() -> Version {
    VERSION
}

/// Message
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[allow(missing_docs)]
#[serde(untagged)]
pub enum Message {
    Connect { connect: Connect },
    Request { request: Request },
    Response { response: Response },
    Notification { notification: Notification },
}

/// Notification / Event
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
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
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum CgroupNotification {
    Memory(MemoryNotification),
}

/// CGroup memory event data
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
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
    Ack { configuration: ConsoleConfiguration },
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
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Request {
    ContainerStats(Container),
    Containers,
    Ident,
    Install(RepositoryId, u64),
    Kill(Container, i32),
    Mount(Vec<Container>),
    Repositories,
    Shutdown,
    Start(
        Container,
        Vec<NonNulString>,
        HashMap<NonNulString, NonNulString>,
    ),
    TokenCreate(Vec<u8>, Vec<u8>),
    TokenVerify(Token, Vec<u8>, Vec<u8>),
    Umount(Vec<Container>),
    Uninstall(Container),
}

/// Token
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Token([u8; 40]);

impl AsRef<[u8]> for Token {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Token> for [u8; 40] {
    fn from(value: Token) -> Self {
        value.0
    }
}

impl From<[u8; 40]> for Token {
    fn from(value: [u8; 40]) -> Self {
        Self(value)
    }
}

/// Token verification result
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
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
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum MountResult {
    Ok { container: Container },
    Error { container: Container, error: Error },
}

/// Result of a umount operation
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum UmountResult {
    Ok { container: Container },
    Error { container: Container, error: Error },
}

/// Response
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Response {
    Ok,
    Error(Error),
    ContainerStats(Container, ContainerStats),
    Containers(Vec<ContainerData>),
    Ident(Container),
    Install(Container),
    Mount(Vec<MountResult>),
    Repositories(HashSet<RepositoryId>),
    Token(Token),
    TokenVerification(VerificationResult),
    Umount(Vec<UmountResult>),
}

/// Container exit status
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
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
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Error {
    Configuration {
        context: String,
    },
    PermissionDenied {
        /// Permissions of this connections
        permissions: HashSet<ConsolePermission>,
        /// Required permission that was denied
        required: ConsolePermission,
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

impl Serialize for Token {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Token {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TokenVisitor;

        impl<'de> Visitor<'de> for TokenVisitor {
            type Value = Token;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a 40 byte sequence")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if v.len() != 40 {
                    return Err(serde::de::Error::custom("token length is 40 bytes"));
                }
                Ok(Token(v.try_into().map_err(|_| {
                    serde::de::Error::custom("token is not 40 bytes")
                })?))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut v = [0u8; 40];
                for b in &mut v {
                    *b = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("token is not 40 bytes"))?;
                }
                Ok(Token(v))
            }
        }

        deserializer.deserialize_bytes(TokenVisitor)
    }
}

impl JsonSchema for Token {
    fn schema_name() -> String {
        "Token".to_string()
    }

    fn json_schema(_: &mut SchemaGenerator) -> schemars::schema::Schema {
        SchemaObject {
            instance_type: Some(InstanceType::Array.into()),
            ..Default::default()
        }
        .into()
    }
}
