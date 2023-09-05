use std::io;

use northstar_runtime::api::model;
use thiserror::Error;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Runtime(#[from] model::Error),
    #[error("invalid protocol version")]
    ProtocolVersion,
    #[error("permission denied")]
    PermissionDenied,
    #[error("notification consumer lagged")]
    LaggedNotifications,
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("connection closed")]
    ConnectionClosed,
    #[error(transparent)]
    Io(#[from] io::Error),
}
