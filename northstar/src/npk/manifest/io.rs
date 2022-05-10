use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// IO configuration for stdin, stdout, stderr
#[derive(Default, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Io {
    /// stdout configuration
    pub stdout: Output,
    /// stderr configuration
    pub stderr: Output,
}

/// Io redirection for stdout/stderr
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub enum Output {
    /// Discard output
    #[serde(rename = "discard")]
    Discard,
    /// Forward output to the logging system with level and optional tag
    #[serde(rename = "pipe")]
    Pipe,
}

impl Default for Output {
    fn default() -> Output {
        Output::Discard
    }
}

/// Log level
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// The "error" level.
    #[serde(alias = "ERROR")]
    Error = 1,
    /// The "warn" level.
    ///
    /// Designates hazardous situations.
    #[serde(alias = "WARN")]
    Warn,
    /// The "info" level.
    ///
    /// Designates useful information.
    #[serde(alias = "INFO")]
    Info,
    /// The "debug" level.
    ///
    /// Designates lower priority information.
    #[serde(alias = "DEBUG")]
    Debug,
    /// The "trace" level.
    ///
    /// Designates very low priority, often extremely verbose, information.
    #[serde(alias = "TRACE")]
    Trace,
}
