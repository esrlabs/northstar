use super::init::Init;
use crate::{
    common::{container::Container, non_nul_string::NonNulString},
    runtime::{ipc::owned_fd::OwnedFd, ExitStatus, Pid},
};
use serde::{Deserialize, Serialize};

/// Request from the runtime to the forker
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    /// Request from the runtime to the forker process to craete a new init process
    /// for a container. The console fd is optional and only present if configured
    /// in the manifest.
    CreateRequest {
        init: Init,
        #[serde(skip)]
        console: Option<OwnedFd>,
    },
    /// Result of a container init creation.
    CreateResult { pid: Pid },
    /// Perfrom a exec from a container init with the given arguments (mainly
    /// from the manifest). The `io` is optional just because to avoid a `Default`
    /// impl for `OwnedFd`. A `ExecRequest` with `io` equals `None` is invalid.
    ExecRequest {
        container: Container,
        path: NonNulString,
        args: Vec<NonNulString>,
        env: Vec<NonNulString>,
        #[serde(skip)]
        io: Option<[OwnedFd; 3]>,
    },
    /// Confirmation message fo a exec request.
    ExecResult,
    /// Something went wrong.
    Error(String),
}

/// Notification from the forker to the runtime
#[derive(Debug, Serialize, Deserialize)]
pub enum Notification {
    Exit {
        container: Container,
        exit_status: ExitStatus,
    },
}
