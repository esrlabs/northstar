use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::common::non_nul_string::NonNulString;

/// SELinux configuration
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Selinux {
    /// Explicit list of allowed syscalls
    pub context: NonNulString,
}
