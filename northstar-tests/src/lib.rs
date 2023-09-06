#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod containers;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod logger;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod runtime;

/// Northstar runtime test.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use northstar_tests_derive::runtime_test;
