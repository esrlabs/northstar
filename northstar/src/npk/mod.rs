use crate::common::version::Version;

/// dm-verity for integrity checking of block devices
pub(crate) mod dm_verity;

/// Container manifest
pub mod manifest;

/// NPK file format
#[allow(clippy::module_inception)]
pub mod npk;

/// NPK version
pub const VERSION: Version = Version::new(0, 0, 1);
