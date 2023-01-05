#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod containers;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod logger;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod runtime;

/// Northstar runtime test. Fixture for testing the Northstar runtime. This fixture start
/// an instance of northstar with a hard coded configuration that uses tempdirs etc. The
/// `client` fn delivers a connected and ready to use `api::client::Client` instance.
///
/// ```rust
/// # use anyhow::Result;
/// # use northstar_client::model::{ExitStatus, Notification};
/// # use northstar_tests::{containers::*, logger::assume, runtime::client, runtime_test};
/// #[runtime_test]
/// fn console() -> Result<()> {
///     client().install(EXAMPLE_CONSOLE_NPK, "mem").await?;
///     client().start(EXAMPLE_CONSOLE).await?;
///     // The console example stop itself - so wait for it...
///     assume("Container console:0.0.1 connected with permissions .*", 5).await?;
///     assume("Killing console:0.0.1 with SIGTERM", 5).await
/// }
/// ```
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use northstar_tests_derive::runtime_test;
