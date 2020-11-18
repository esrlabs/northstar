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

#[cfg(any(target_os = "android", target_os = "linux"))]
use super::linux::{device_mapper, mount};
#[cfg(any(target_os = "android", target_os = "linux"))]
use super::linux::{inotify, loopdev};
use super::Name;
use crate::api::InstallationResult;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("No application found")]
    ApplicationNotFound,
    #[error("Application is not running")]
    ApplicationNotRunning,
    #[error("Missing resource {0}")]
    MissingResource(String),
    #[error("Process error: {0}")]
    Process(super::process::Error),
    #[error("Application(s) \"{0:?}\" is/are running")]
    ApplicationRunning(Vec<Name>),
    #[error("Failed to install")]
    Installation(InstallationError),
    #[error("Failed to uninstall")]
    UninstallationError(InstallationError),
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
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[error("Minijail error: {0}")]
    Minijail(super::linux::minijail::Error),
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[error("CGroups error: {0}")]
    CGroup(super::linux::cgroups::Error),
    #[error("Key error: {0}")]
    KeyError(super::keys::Error),
    #[error("Internal error: {0}")]
    Internal(&'static str),
    #[error("Wrong permissions: {0}")]
    FsPermissions(String),
}

#[derive(Error, Debug)]
pub enum InstallationError {
    #[error("ZIP error")]
    Zip(#[from] zip::result::ZipError),
    #[error("Signature file invalid ({0})")]
    SignatureFileInvalid(String),
    #[error("Malformed signature")]
    MalformedSignature,
    #[error("Hashes malformed ({0})")]
    MalformedHashes(String),
    #[error("Failed to verify manifest: {0}")]
    MalformedManifest(String),
    #[error("Problem verifiing content with signature ({0})")]
    SignatureVerificationError(String),
    #[error("Verity device mapper problem ({0})")]
    VerityError(String),
    #[error("Missing verity header")]
    NoVerityHeader,
    #[error("Unsupported verity version {0}")]
    UnexpectedVerityVersion(u32),
    #[error("Unsupported verity algorithm: {0}")]
    UnexpectedVerityAlgorithm(String),
    #[error("Application {0} already installed")]
    ApplicationAlreadyInstalled(String),
    #[error("Archive error: {0}")]
    ArchiveError(String),
    #[error("Timeout: {0}")]
    Timeout(String),
    #[error("Duplicate resource")]
    DuplicateResource,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[error("Device mapper error: {0}")]
    DeviceMapper(device_mapper::Error),
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[error("Loop device error: {0}")]
    LoopDeviceError(loopdev::Error),
    #[error("Hash error: {0}")]
    HashInvalid(String),
    #[error("Key missing: {0}")]
    KeyNotFound(String),
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[error("Failed to mount")]
    Mount(#[from] mount::Error),
    #[error("Inotify")]
    #[cfg(any(target_os = "android", target_os = "linux"))]
    INotify(#[from] inotify::Error),
    #[error("IO error: {context}")]
    Io {
        context: String,
        #[source]
        error: io::Error,
    },
}

impl From<InstallationError> for InstallationResult {
    fn from(error: InstallationError) -> InstallationResult {
        match error {
            InstallationError::Zip(_) => InstallationResult::FileCorrupted,
            InstallationError::SignatureFileInvalid(_) => InstallationResult::SignatureFileInvalid,
            InstallationError::MalformedSignature => InstallationResult::MalformedSignature,
            InstallationError::MalformedHashes(_) => InstallationResult::MalformedHashes,
            InstallationError::MalformedManifest(s) => InstallationResult::MalformedManifest(s),
            InstallationError::VerityError(s) => InstallationResult::VerityProblem(s),
            InstallationError::ArchiveError(s) => InstallationResult::ArchiveError(s),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            InstallationError::DeviceMapper(e) => {
                InstallationResult::DeviceMapperProblem(format!("{:?}", e))
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            InstallationError::LoopDeviceError(e) => {
                InstallationResult::LoopDeviceError(format!("{}", e))
            }
            InstallationError::HashInvalid(s) => InstallationResult::HashInvalid(s),
            InstallationError::KeyNotFound(s) => InstallationResult::KeyNotFound(s),
            InstallationError::ApplicationAlreadyInstalled(_) => {
                InstallationResult::ApplicationAlreadyInstalled
            }
            InstallationError::Io { context, error: _ } => {
                InstallationResult::FileIoProblem(context)
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            InstallationError::Mount(e) => InstallationResult::MountError(format!("{}", e)),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            InstallationError::INotify(e) => InstallationResult::INotifyError(format!("{}", e)),
            InstallationError::Timeout(s) => InstallationResult::TimeoutError(s),
            InstallationError::NoVerityHeader => {
                InstallationResult::VerityProblem("Verity header missing".to_string())
            }
            InstallationError::UnexpectedVerityAlgorithm(s) => {
                InstallationResult::VerityProblem(format!("Unexpected verity algorithm: {}", s))
            }
            InstallationError::UnexpectedVerityVersion(n) => {
                InstallationResult::VerityProblem(format!("Unexpected verity version: {}", n))
            }
            InstallationError::SignatureVerificationError(s) => {
                InstallationResult::SignatureVerificationFailed(s)
            }
            InstallationError::DuplicateResource => InstallationResult::DuplicateResource,
        }
    }
}
