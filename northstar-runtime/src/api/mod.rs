use crate::common::version::Version;
use pkg_version::{pkg_version_major, pkg_version_minor, pkg_version_patch};

/// API protocol codec
pub mod codec;
/// API model
pub mod model;

/// API version
pub const VERSION: Version = Version::new(
    pkg_version_major!(),
    pkg_version_minor!(),
    pkg_version_patch!(),
);
