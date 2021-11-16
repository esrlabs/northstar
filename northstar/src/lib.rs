//! Northstar container runtime

#![deny(missing_docs)]
#![deny(clippy::all)]

/// Common internal types used in Northstar
pub mod common;

#[cfg(feature = "api")]
/// Northstar remote API. Control start and stop of applications and
/// receive updates about container states.
pub mod api;

#[cfg(feature = "npk")]
/// Northstar package format and utils
pub mod npk;

#[cfg(feature = "runtime")]
/// The Northstar runtime
pub mod runtime;

#[cfg(feature = "seccomp")]
/// Support for seccomp syscall filtering
pub mod seccomp;
