use serde::{Deserialize, Serialize};

use crate::common::non_nul_string::NonNulString;

/// Container network configuration. Either join the host network or
/// an existing network namespace. In order to create a new network
/// namespace for the container, omit the network confuration in the
/// manifest.
#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    /// Join the host network.
    #[serde(rename = "host")]
    Host,
    /// Join an existing namespace.
    #[serde(rename = "namespace")]
    Namespace(NonNulString),
}
