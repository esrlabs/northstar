use crate::common::non_null_string::NonNullString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Predefined seccomp profile
#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Profile {
    /// Default seccomp filter similar to docker's default profile
    #[serde(rename = "default")]
    Default,
}

/// Seccomp configuration
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Seccomp {
    /// Pre-defined seccomp profile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    /// Explicit list of allowed syscalls
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<HashMap<NonNullString, SyscallRule>>,
}

/// SELinux configuration
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Selinux {
    /// Explicit list of allowed syscalls
    pub context_type: NonNullString,
}

/// Syscall rule
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub enum SyscallRule {
    /// Any syscall argument is allowed
    #[serde(rename = "any")]
    Any,
    /// Explicit list of allowed syscalls arguments
    #[serde(rename = "args")]
    Args(SyscallArgRule),
}

/// Syscall argument rule
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SyscallArgRule {
    /// Index of syscall argument
    pub index: usize,
    /// Value of syscall argument
    pub values: Option<Vec<u64>>,
    /// Bitmask of syscall argument
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<u64>,
}
