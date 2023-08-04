use serde::Deserialize;
use tokio::time;

use crate::runtime::config::ConsoleOptions;

/// Console Quality of Service
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    /// Token validity duration.
    pub token_validity: time::Duration,
    /// Limits the number of requests processed per second.
    pub max_requests_per_sec: usize,
    /// Maximum request size in bytes
    pub max_request_size: u64,
    /// Maximum npk size in bytes.
    pub max_npk_install_size: u64,
    /// NPK stream timeout in seconds.
    pub npk_stream_timeout: time::Duration,
}

impl From<ConsoleOptions> for Options {
    fn from(value: ConsoleOptions) -> Self {
        Self {
            token_validity: value.token_validity,
            max_requests_per_sec: value.max_requests_per_sec,
            max_request_size: value.max_request_size,
            max_npk_install_size: value.max_npk_install_size,
            npk_stream_timeout: value.npk_stream_timeout,
        }
    }
}
