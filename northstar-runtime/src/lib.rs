//! Northstar container runtime

#![deny(missing_docs)]
#![deny(
    clippy::all,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::unwrap_used
)]

/// Common internal types used in Northstar.
pub mod common;

/// Northstar remote API. Control start and stop of applications and
/// receive updates about container states.
#[cfg(feature = "api")]
pub mod api;

/// Northstar package format and utils.
#[cfg(feature = "npk")]
pub mod npk;

/// The Northstar runtime.
#[cfg(feature = "runtime")]
pub mod runtime;

/// Support for seccomp syscall filtering.
#[cfg(feature = "seccomp")]
pub mod seccomp;

/// Reexec.
#[cfg(feature = "rexec")]
mod rexec;

/// Replace /proc/self/exe with a read-only and sealed memfd and (re)exeve.
#[cfg(feature = "rexec")]
pub use rexec::rexec;
