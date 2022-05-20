use crate::common::version::Version;

/// API protocol codec
pub mod codec;
/// API model
pub mod model;

/// API version
pub const VERSION: Version = Version::new(0, 3, 0);
