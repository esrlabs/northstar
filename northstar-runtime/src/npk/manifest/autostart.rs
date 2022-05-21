use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Autostart options
#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Autostart {
    /// Ignore errors when starting this container. Ignore the containers termination result
    #[serde(rename = "relaxed")]
    Relaxed,
    /// Exit the runtime if starting this containers fails or the container exits with a non zero exit code.
    /// Use this variant to propagate errors with a container to the system above the runtime e.g init.
    #[serde(rename = "critical")]
    Critical,
}
