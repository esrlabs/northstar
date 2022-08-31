use std::os::unix::prelude::OwnedFd;

use super::init::Init;
use crate::{
    common::{container::Container, non_nul_string::NonNulString},
    runtime::{ExitStatus, Pid},
};
use serde::{Deserialize, Serialize};

/// Messages exchanged between the runtime and the forker process.
#[derive(Debug)]
pub enum Message {
    /// Request from the runtime to the forker process to create a new init process
    /// for a container. The console fd is optional and only present if configured
    /// in the manifest.
    CreateRequest {
        init: Init,
        io: [OwnedFd; 3],
        console: Option<OwnedFd>,
    },
    /// Result of a container creation.
    CreateResult { result: Result<Pid, String> },
    /// Perfrom an exec from a container init with the given arguments.
    ExecRequest {
        container: Container,
        path: NonNulString,
        args: Vec<NonNulString>,
        env: Vec<NonNulString>,
    },
    /// Confirmation message for a exec request.
    ExecResult,
}

/// Notification from the forker to the runtime.
#[derive(Debug, Serialize, Deserialize)]
pub enum Notification {
    Exit {
        container: Container,
        exit_status: ExitStatus,
    },
}
