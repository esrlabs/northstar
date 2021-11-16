use std::path::PathBuf;

use super::init::Init;
use crate::{
    common::container::Container,
    runtime::{ipc::owned_fd::OwnedFd, ExitStatus, Pid},
};
use derive_new::new;
use serde::{Deserialize, Serialize};

/// Request from the runtime to the forker
#[non_exhaustive]
#[derive(new, Debug, Serialize, Deserialize)]
pub enum Message {
    CreateRequest {
        init: Init,
        #[serde(skip)]
        console: Option<OwnedFd>,
    },
    CreateResult {
        init: Pid,
    },
    ExecRequest {
        container: Container,
        path: PathBuf,
        args: Vec<String>,
        env: Vec<String>,
        #[serde(skip)]
        io: Option<[OwnedFd; 3]>,
    },
    ExecResult,
    Failure(String),
}

/// Notification from the forker to the runtime
#[derive(Debug, Serialize, Deserialize)]
pub enum Notification {
    Exit {
        container: Container,
        exit_status: ExitStatus,
    },
}
