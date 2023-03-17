use serde::{Deserialize, Serialize};

/// IO configuration for stdin, stdout, stderr
#[derive(Default, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Io {
    /// stdout configuration
    pub stdout: Output,
    /// stderr configuration
    pub stderr: Output,
}

/// Io redirection for stdout/stderr
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Default)]
pub enum Output {
    /// Discard output
    #[serde(rename = "discard")]
    #[default]
    Discard,
    /// Forward output to the logging system with level and optional tag
    #[serde(rename = "pipe")]
    Pipe,
    /// Inherit stdout/stderr from the runtime
    #[serde(rename = "inherit")]
    Inherit,
}
