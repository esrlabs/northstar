use crate::common::non_nul_string::NonNulString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Predefined seccomp profile
#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// Default seccomp filter similar to docker's default profile
    Default,
}

/// Seccomp configuration
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seccomp {
    /// Pre-defined seccomp profile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    /// Explicit list of allowed syscalls
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<HashMap<NonNulString, SyscallRule>>,
}

/// Syscall rule
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum SyscallRule {
    /// Any syscall argument is allowed
    Any,
    /// Explicit list of allowed syscalls arguments
    Args(SyscallArgRule),
}

/// Syscall argument rule
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyscallArgRule {
    /// Index of syscall argument
    pub index: usize,
    /// Value of syscall argument
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<u64>>,
    /// Bitmask of syscall argument
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<u64>,
}
