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
    Name,
};
use crate::api::InstallationResult;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    // process
    #[error("Process error: {0}")]
    Process(super::process::Error),
    // linux
    #[error("Linux error")]
    Linux(#[from] linux::Error),
    #[error("Failed to uninstall")]
    UninstallationError(linux::Error),
    // linux -- cgroups
    #[error("CGroups error: {0}")]
    CGroup(super::linux::cgroups::Error),
    // keys
    #[error("Key error: {0}")]
    KeyError(super::keys::Error),
    // npk
    #[error("NPK error: {0}")]
    NpkError(npk::Error),

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
    #[error("OS error: {context}")]
    Os {
        context: String,
        #[source]
        error: nix::Error,
    },
    #[error("IO error: {context}")]
    Io {
        context: String,
        #[source]
        error: io::Error,
    },
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Minijail error: {0}")]
    Minijail(super::linux::minijail::Error),
    #[error("Internal error: {0}")]
    Internal(&'static str),
    #[error("Wrong permissions: {0}")]
    FsPermissions(String),
}

#[derive(Error, Debug)]
pub enum InstallationError {
    #[error("Application {0} already installed")]
    ApplicationAlreadyInstalled(String),
    #[error("Duplicate resource")]
    DuplicateResource,
}

impl From<Error> for InstallationResult {
    fn from(error: Error) -> InstallationResult {
        // TODO error translation to API
        InstallationResult::ApplicationAlreadyInstalled
        // match error {
        //     _ => unreachable!()
        //     // InstallationError::Zip(_) => InstallationResult::FileCorrupted,
        //     // InstallationError::SignatureFileInvalid(_) => InstallationResult::SignatureFileInvalid,
        //     // InstallationError::MalformedSignature => InstallationResult::MalformedSignature,
        //     // InstallationError::MalformedHashes(_) => InstallationResult::MalformedHashes,
        //     // InstallationError::MalformedManifest(s) => InstallationResult::MalformedManifest(s),
        //     // InstallationError::VerityError(s) => InstallationResult::VerityProblem(s),
        //     // InstallationError::ArchiveError(s) => InstallationResult::ArchiveError(s),
        //     // #[cfg(any(target_os = "android", target_os = "linux"))]
        //     // InstallationError::DeviceMapper(e) => {
        //     //     InstallationResult::DeviceMapperProblem(format!("{:?}", e))
        //     // }
        //     // #[cfg(any(target_os = "android", target_os = "linux"))]
        //     // InstallationError::LoopDeviceError(e) => {
        //     //     InstallationResult::LoopDeviceError(format!("{}", e))
        //     // }
        //     // InstallationError::HashInvalid(s) => InstallationResult::HashInvalid(s),
        //     // InstallationError::KeyNotFound(s) => InstallationResult::KeyNotFound(s),
        //     // InstallationError::ApplicationAlreadyInstalled(_) => {
        //     //     InstallationResult::ApplicationAlreadyInstalled
        //     // }
        //     // InstallationError::Io { context, error: _ } => {
        //     //     InstallationResult::FileIoProblem(context)
        //     // }
        //     // #[cfg(any(target_os = "android", target_os = "linux"))]
        //     // InstallationError::Mount(e) => InstallationResult::MountError(format!("{}", e)),
        //     // #[cfg(any(target_os = "android", target_os = "linux"))]
        //     // InstallationError::INotify(e) => InstallationResult::INotifyError(format!("{}", e)),
        //     // InstallationError::Timeout(s) => InstallationResult::TimeoutError(s),
        //     // InstallationError::NoVerityHeader => {
        //     //     InstallationResult::VerityProblem("Verity header missing".to_string())
        //     // }
        //     // InstallationError::UnexpectedVerityAlgorithm(s) => {
        //     //     InstallationResult::VerityProblem(format!("Unexpected verity algorithm: {}", s))
        //     // }
        //     // InstallationError::UnexpectedVerityVersion(n) => {
        //     //     InstallationResult::VerityProblem(format!("Unexpected verity version: {}", n))
        //     // }
        //     // InstallationError::SignatureVerificationError(s) => {
        //     //     InstallationResult::SignatureVerificationFailed(s)
        //     // }
        //     // InstallationError::DuplicateResource => InstallationResult::DuplicateResource,
        // }
    }
}
