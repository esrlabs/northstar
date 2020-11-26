// Copyright (c) 2019 - 2020 ESRLabs
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

use super::{
    linux::{self},
    process::Error as ProcessError,
    Name,
};
use crate::api::ApiError;
use ed25519_dalek::SignatureError;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    // process
    #[error("Process error: {0}")]
    Process(ProcessError),
    // linux
    #[error("Linux error")]
    Linux(#[from] linux::Error),
    // keys
    #[error("Key error: {0}")]
    KeyError(#[from] SignatureError),
    // npk
    #[error("NPK error: {0}")]
    Npk(npk::Error),

    // installation
    #[error("Failed to install")]
    Installation(InstallationError),

    #[error("No application found")]
    ApplicationNotFound,
    #[error("Application is not running")]
    ApplicationNotRunning,
    #[error("Missing resource {0}")]
    MissingResource(String),
    #[error("Application(s) \"{0:?}\" is/are running")]
    ApplicationRunning(Vec<Name>),
    #[error("IO error: {0}")]
    Io(String, #[source] io::Error),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Error, Debug)]
pub enum InstallationError {
    #[error("Application {0} already installed")]
    ApplicationAlreadyInstalled(String),
    #[error("Duplicate resource")]
    DuplicateResource,
}

impl From<Error> for ApiError {
    fn from(error: Error) -> ApiError {
        match error {
            Error::Process(ProcessError::Start(s)) => ApiError::StartProcess(s),
            Error::Process(ProcessError::Stop) => ApiError::StopProcess,
            Error::Process(ProcessError::WrongContainerType(s)) => ApiError::WrongContainerType(s),
            Error::Process(ProcessError::Minijail(e)) => ApiError::ProcessJail(format!("{}", e)),
            Error::Process(ProcessError::Io { context, error: _r }) => ApiError::ProcessIo(context),
            Error::Process(ProcessError::Os { context, error: _r }) => ApiError::ProcessOs(context),
            Error::Linux(linux::Error::Mount(e)) => ApiError::LinuxMount(format!("{:?}", e)),
            Error::Linux(linux::Error::Unshare(context, _e)) => ApiError::LinuxUnshare(context),
            Error::Linux(linux::Error::Pipe(e)) => ApiError::LinuxPipe(format!("{}", e)),
            Error::Linux(linux::Error::DeviceMapper(e)) => {
                ApiError::LinuxDeviceMapper(format!("{:?}", e))
            }
            Error::Linux(linux::Error::LoopDevice(e)) => {
                ApiError::LinuxLoopDevice(format!("{:?}", e))
            }
            Error::Linux(linux::Error::INotify(e)) => ApiError::LinuxINotifiy(format!("{:?}", e)),
            Error::Linux(linux::Error::CGroup(e)) => ApiError::LinuxCGroups(format!("{:?}", e)),
            Error::Linux(linux::Error::FileOperation(context, error)) => match error.kind() {
                io::ErrorKind::NotFound => ApiError::IoNotFound(context),
                io::ErrorKind::PermissionDenied => ApiError::IoPermissionDenied(context),
                io::ErrorKind::NotConnected => ApiError::IoNotConnected(context),
                io::ErrorKind::BrokenPipe => ApiError::IoBrokenPipe(context),
                io::ErrorKind::AlreadyExists => ApiError::IoAlreadyExists(context),
                io::ErrorKind::InvalidInput => ApiError::IoInvalidInput(context),
                io::ErrorKind::InvalidData => ApiError::IoInvalidData(context),
                io::ErrorKind::TimedOut => ApiError::TimedOut(context),
                _ => ApiError::Io(context),
            },
            Error::KeyError(s) => ApiError::KeyError(format!("Key signature error: {}", s)),
            Error::Npk(e) => ApiError::Npk(format!("Error with npk: {:?}", e)),
            Error::Installation(e) => match e {
                InstallationError::ApplicationAlreadyInstalled(_) => {
                    ApiError::ApplicationAlreadyInstalled
                }
                InstallationError::DuplicateResource => ApiError::DuplicateResource,
            },
            Error::ApplicationNotFound => ApiError::ApplicationNotFound,
            Error::ApplicationNotRunning => ApiError::ApplicationNotRunning,
            Error::ApplicationRunning(_) => ApiError::ApplicationRunning,
            Error::MissingResource(s) => ApiError::MissingResource(s),
            Error::Io(context, _e) => ApiError::IoError(context),
            Error::Protocol(s) => ApiError::Protocol(s),
            Error::Configuration(s) => ApiError::Configuration(s),
            Error::Internal(s) => ApiError::Internal(s),
        }
    }
}
