use crate::common::version::Version;

/// Client to interact with a runtime instance
pub mod client;
/// API protocol codec
pub mod codec;
/// API model
pub mod model;

/// API version
pub const VERSION: Version = Version::new(0, 3, 0);
