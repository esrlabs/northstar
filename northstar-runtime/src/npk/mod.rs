use crate::common::version::Version;
use pkg_version::{pkg_version_major, pkg_version_minor, pkg_version_patch};

/// dm-verity for integrity checking of block devices
pub(crate) mod dm_verity;

/// Container manifest
pub mod manifest;

/// NPK file format
#[allow(clippy::module_inception)]
pub mod npk;

/// API version
pub const VERSION: Version = Version::new(
    pkg_version_major!(),
    pkg_version_minor!(),
    pkg_version_patch!(),
);

#[cfg(test)]
mod tests;
