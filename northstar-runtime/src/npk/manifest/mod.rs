use crate::{
    common::{container::Container, name::Name, non_nul_string::NonNulString, version::Version},
    seccomp::Seccomp,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{
    rust::{maps_duplicate_key_is_error, sets_duplicate_value_is_error},
    skip_serializing_none,
};
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};
use thiserror::Error;
use validator::{Validate, ValidationError, ValidationErrors};

use self::network::Network;

/// Autostart
pub mod autostart;
/// Linux capabilities
pub mod capabilities;
/// Linux control groups
pub mod cgroups;
/// Northstar console configuration
pub mod console;
/// Container io
pub mod io;
/// Container mounts
pub mod mount;
/// Networking
pub mod network;
/// Linux resource limits
pub mod rlimit;
/// Scheduling
pub mod sched;
/// Seccomp
pub mod seccomp;
/// SE Linux
pub mod selinux;
/// Sockets
pub mod socket;

#[cfg(test)]
mod test;

/// Maximum number of supplementary groups
const MAX_SUPPL_GROUPS: usize = 64;
/// Max length of a supplementary group name
const MAX_SUPPL_GROUP_LENGTH: usize = 64;
/// Maximum number of environment variables
const MAX_ENV_VARS: usize = 64;
/// Maximum length of a environment variable name
const MAX_ENV_VAR_NAME_LENGTH: usize = 64;
/// Maximum length of a environment variable value
const MAX_ENV_VAR_VALUE_LENTH: usize = 1024;
/// Environment varibables used by the runtime and not available to the user.
const RESERVED_ENV_VARIABLES: &[&str] = &[
    "NORTHSTAR_NAME",
    "NORTHSTAR_VERSION",
    "NORTHSTAR_CONTAINER",
    "NORTHSTAR_CONSOLE",
];

/// Manifest parsing error
#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum Error {
    #[error("invalid manifest: {0}")]
    Validation(ValidationErrors),
    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    TomlDe(#[from] toml::de::Error),
    #[error(transparent)]
    TomlSer(#[from] toml::ser::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Northstar package manifest
#[skip_serializing_none]
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
#[validate(schema(function = "validate"))]
pub struct Manifest {
    /// Name of container
    pub name: Name,
    /// Container version
    pub version: Version,
    /// Pass a console fd number in NORTHSTAR_CONSOLE
    pub console: Option<console::Console>,
    /// Path to init
    #[validate(length(min = 1, max = 4096))]
    pub init: Option<NonNulString>,
    /// Additional arguments for the application invocation
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<NonNulString>,
    /// Environment passed to container
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    #[validate(custom = "validate_env")]
    pub env: HashMap<NonNulString, NonNulString>,
    /// UID
    #[validate(range(min = 1, message = "uid must be greater than 0"))]
    pub uid: u16,
    /// GID
    #[validate(range(min = 1, message = "gid must be greater than 0"))]
    pub gid: u16,
    /// Scheduling parameter.
    #[validate]
    pub sched: Option<sched::Sched>,
    /// List of bind mounts and resources
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        deserialize_with = "maps_duplicate_key_is_error::deserialize"
    )]
    #[validate(custom = "mount::validate")]
    pub mounts: HashMap<mount::MountPoint, mount::Mount>,
    /// Autostart this container upon northstar startup
    pub autostart: Option<autostart::Autostart>,
    /// CGroup configuration
    pub cgroups: Option<self::cgroups::CGroups>,
    /// Network configuration. Unshare the network if omitted.
    #[validate(custom = "network::validate")]
    pub network: Option<Network>,
    /// Seccomp configuration
    #[validate(custom = "seccomp::validate")]
    pub seccomp: Option<Seccomp>,
    /// SELinux configuration
    #[validate]
    pub selinux: Option<selinux::Selinux>,
    /// Capabilities
    #[serde(
        default,
        skip_serializing_if = "HashSet::is_empty",
        deserialize_with = "sets_duplicate_value_is_error::deserialize"
    )]
    pub capabilities: HashSet<capabilities::Capability>,
    /// String containing group names to give to new container
    #[serde(
        default,
        skip_serializing_if = "HashSet::is_empty",
        deserialize_with = "sets_duplicate_value_is_error::deserialize"
    )]
    #[validate(custom = "validate_suppl_groups")]
    pub suppl_groups: HashSet<NonNulString>,
    /// Resource limits
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        deserialize_with = "maps_duplicate_key_is_error::deserialize"
    )]
    pub rlimits: HashMap<rlimit::RLimitResource, rlimit::RLimitValue>,
    /// Sockets.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub sockets: HashMap<NonNulString, socket::Socket>,
    /// IO configuration
    #[serde(default)]
    pub io: Option<io::Io>,
    /// Optional custom data. The runtime doesn't use this.
    pub custom: Option<Value>,
}

impl Manifest {
    /// Container that is specified in the manifest.
    pub fn container(&self) -> Container {
        Container::new(self.name.clone(), self.version.clone())
    }

    /// Read a manifest from `reader`.
    pub fn from_reader<R: std::io::Read>(mut reader: R) -> Result<Self, Error> {
        let mut buf = String::new();
        reader
            .read_to_string(&mut buf)
            .map_err(Error::Io)
            .and_then(|_| Manifest::from_str(&buf))
    }
}

impl FromStr for Manifest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let manifest: Manifest = if let Ok(manifest) = serde_yaml::from_str(s) {
            manifest
        } else if let Ok(manifest) = serde_json::from_str(s) {
            manifest
        } else {
            toml::de::from_str(s).map_err(Error::TomlDe)?
        };

        manifest.validate().map_err(Error::Validation)?;
        Ok(manifest)
    }
}

/// Validate manifest.
fn validate(manifest: &Manifest) -> Result<(), ValidationError> {
    // Most optionals in the manifest are not valid for a resource container
    if manifest.init.is_none()
        && (!manifest.args.is_empty()
            || !manifest.capabilities.is_empty()
            || !manifest.env.is_empty()
            || !manifest.suppl_groups.is_empty()
            || manifest.autostart.is_some()
            || manifest.cgroups.is_some()
            || manifest.io.is_some()
            || manifest.seccomp.is_some())
    {
        return Err(ValidationError::new(
            "resource containers must not define any of the following manifest entries:\
                args, env, autostart, cgroups, seccomp, capabilities, suppl_groups, io",
        ));
    }

    Ok(())
}

/// Validate supplementary groups for number and length.
fn validate_suppl_groups(groups: &HashSet<NonNulString>) -> Result<(), ValidationError> {
    if groups.len() > MAX_SUPPL_GROUPS {
        return Err(ValidationError::new(
            "supplementary groups exceeds max length",
        ));
    }

    if groups.iter().any(|g| g.len() > MAX_SUPPL_GROUP_LENGTH) {
        return Err(ValidationError::new(
            "supplementary group name exceeds max length",
        ));
    }
    Ok(())
}

/// Validate the map of environment variables. They shall not contain reserved variable names
/// that are used by the runtime.
fn validate_env(env: &HashMap<NonNulString, NonNulString>) -> Result<(), ValidationError> {
    // Check the number of env variables
    if env.len() > MAX_ENV_VARS {
        return Err(ValidationError::new("env exceeds max length"));
    }

    // Check the lenght of each env variable name
    if env.keys().any(|k| k.len() > MAX_ENV_VAR_NAME_LENGTH) {
        return Err(ValidationError::new("env variable name exceeds max length"));
    }

    // Check the lenght of each env variable value
    if env.values().any(|v| v.len() > MAX_ENV_VAR_VALUE_LENTH) {
        return Err(ValidationError::new("env value exceeds max length"));
    }

    // Check for reserved env variable names
    if RESERVED_ENV_VARIABLES.iter().any(|key| {
        env.contains_key(unsafe { &NonNulString::from_str_unchecked(key) }) // safe - constants
    }) {
        Err(ValidationError::new("reserved env variable name"))
    } else {
        Ok(())
    }
}
