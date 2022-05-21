use thiserror::Error;

/// API error
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum RequestError {
    #[error("runtime error: {0:?}")]
    Runtime(northstar_runtime::api::model::Error),
    #[error("notification consumer lagged")]
    LaggedNotifications,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

/// Connection establishment error
#[derive(Error, Debug)]
#[error(transparent)]
pub struct ConnectionError(#[from] anyhow::Error);

/// Errors for Client creation from env var
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum FromEnvError {
    #[error("invalid NORTHSTAR_CONSOLE value: {0}")]
    EnvVar(#[from] anyhow::Error),
    #[error(transparent)]
    ClientCreation(#[from] ClientError),
}

/// Errors while creating client
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("connection establishment timed out")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error(transparent)]
    ConnectionError(#[from] ConnectionError),
}
