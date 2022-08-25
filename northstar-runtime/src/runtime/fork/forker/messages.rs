use std::os::unix::prelude::OwnedFd;

use super::init::Init;
use crate::{
    common::{container::Container, non_nul_string::NonNulString},
    runtime::{ExitStatus, Pid},
};
use serde::{Deserialize, Serialize};

/// Messages between the runtime and the forker process
#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    /// Request from the runtime to the forker process to craete a new init process
    /// for a container. The console fd is optional and only present if configured
    /// in the manifest. The `io` is *not* optional and just optional to satisfy
    /// serde's requirement of `Default`.
    CreateRequest {
        init: Init,
        #[serde(skip)]
        io: Option<[OwnedFd; 3]>,
        #[serde(skip)]
        console: Option<OwnedFd>,
    },
    /// Result of a container init creation.
    CreateResult { result: Result<Pid, String> },
    /// Perfrom a exec from a container init with the given arguments (mainly
    /// from the manifest).
    ExecRequest {
        container: Container,
        path: NonNulString,
        args: Vec<NonNulString>,
        env: Vec<NonNulString>,
    },
    /// Confirmation message fo a exec request.
    ExecResult,
}

/// Notification from the forker to the runtime
#[derive(Debug, Serialize, Deserialize)]
pub enum Notification {
    Exit {
        container: Container,
        exit_status: ExitStatus,
    },
}
