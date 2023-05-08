use serde::{Deserialize, Serialize};
use validator::ValidationError;

use crate::common::non_nul_string::NonNulString;

/// Max length of a network namespace
const MAX_NET_NAMESPACE_LENGTH: usize = 256;

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

/// Validate network namespace setting
pub fn validate(network: &Network) -> Result<(), ValidationError> {
    match network {
        Network::Host => Ok(()),
        Network::Namespace(netns) if netns.len() <= MAX_NET_NAMESPACE_LENGTH => Ok(()),
        Network::Namespace(_) => Err(ValidationError::new("network namespace exceeds max length")),
    }
}
