pub mod containers;
pub mod logger;
pub mod runtime;

/// Northstar runtime test
///
/// ```rust
/// # use anyhow::Result;
/// # use northstar::api::model::{ExitStatus, Notification};
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
pub use northstar_tests_derive::runtime_test;
