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

use crate::runtime::{InstallationResult, Name};
use anyhow::Error as AnyhowError;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("No application found")]
    ApplicationNotFound,
    #[error("Missing resouce {0}")]
    MissingResource(String),
    #[error("Failed to spawn process: {0}")]
    ProcessError(AnyhowError),
    #[error("Application(s) \"{0:?}\" is/are running")]
    ApplicationRunning(Vec<Name>),
    #[error("Failed to uninstall")]
    UninstallationError(AnyhowError),
    #[error("Application is not running")]
    ApplicationNotRunning,
}

#[derive(Error, Debug)]
pub enum InstallFailure {
    #[error("File seems to be corrupted")]
    FileCorrupted,
    #[error("No signature found")]
    SignatureNotFound,
    #[error("Signature file invalid")]
    InvalidSignatureYaml,
    #[error("Signature malformed")]
    MalformedSignature,
    #[error("Hashes malformed")]
    MalformedHashes,
    #[error("Problem verifiing the manifest ({0})")]
    MalformedManifest(String),
    #[error("Verity device mapper problem ({0})")]
    VerityProblem(String),
    #[error("Verity header not found")]
    NoVerityHeader,
    #[error("Verity version {0} not supported")]
    UnexpectedVerityVersion(u32),
    #[error("Verity algorithm {0} not supported")]
    UnexpectedVerityAlgorithm(String),
    #[error("Problem with archive ({0})")]
    ArchiveError(String),
    #[error("Problem with device mapper")]
    DeviceMapperProblem(DeviceMapperError),
    #[error("Problem with loop device")]
    LoopDeviceError(LoopDeviceError),
    #[error("Hash is invalid ({0})")]
    HashInvalid(String),
    #[error("No signature key found ({0})")]
    KeyNotFound(String),
    #[error("Cannot install application {0}, already exists")]
    ApplicationAlreadyInstalled(String),
    #[error("Failure to mount: {context}")]
    MountError {
        context: String,
        #[source]
        error: nix::Error,
    },
    #[error("Internal error: {context}")]
    InternalError {
        context: String,
        #[source]
        error: io::Error,
    },
}

impl From<InstallFailure> for InstallationResult {
    fn from(failure: InstallFailure) -> InstallationResult {
        match failure {
            InstallFailure::FileCorrupted => InstallationResult::FileCorrupted,
            InstallFailure::SignatureNotFound => InstallationResult::SignatureNotFound,
            InstallFailure::InvalidSignatureYaml => InstallationResult::InvalidSignatureYaml,
            InstallFailure::MalformedSignature => InstallationResult::MalformedSignature,
            InstallFailure::MalformedHashes => InstallationResult::MalformedHashes,
            InstallFailure::MalformedManifest(s) => InstallationResult::MalformedManifest(s),
            InstallFailure::VerityProblem(s) => InstallationResult::VerityProblem(s),
            InstallFailure::ArchiveError(s) => InstallationResult::ArchiveError(s),
            InstallFailure::DeviceMapperProblem(e) => {
                InstallationResult::DeviceMapperProblem(format!("{:?}", e))
            }
            InstallFailure::LoopDeviceError(e) => {
                InstallationResult::LoopDeviceError(format!("{}", e))
            }
            InstallFailure::HashInvalid(s) => InstallationResult::HashInvalid(s),
            InstallFailure::KeyNotFound(s) => InstallationResult::KeyNotFound(s),
            InstallFailure::ApplicationAlreadyInstalled(_) => {
                InstallationResult::ApplicationAlreadyInstalled
            }
            InstallFailure::InternalError { context, error: _ } => {
                InstallationResult::InternalError(context)
            }
            InstallFailure::MountError { context, error: _ } => {
                InstallationResult::MountError(context)
            }
            InstallFailure::NoVerityHeader => InstallationResult::NoVerityHeader,
            InstallFailure::UnexpectedVerityAlgorithm(s) => {
                InstallationResult::UnexpectedVerityAlgorithm(s)
            }
            InstallFailure::UnexpectedVerityVersion(n) => {
                InstallationResult::UnexpectedVerityVersion(n)
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum DeviceMapperError {
    #[error("Failure opening file for device mapper")]
    OpenDmFailed(#[from] io::Error),
    #[error("Failure issuing an IO-CTL call")]
    IoCtrlFailed(#[from] nix::Error),
    #[error("Response DM buffer requires too much space")]
    BufferFull,
    #[error("Failure to suspend device")]
    SuspendDeviceFailed,
}

#[derive(Error, Debug)]
pub enum LoopDeviceError {
    #[error("Control file for loop device could not be created")]
    ControlFileNotCreated(#[from] io::Error),
    #[error("Failure to find or allocate free loop device")]
    NoFreeDeviceFound,
    #[error("Failure adding new loop device")]
    DeviceAlreadyAllocated,
    #[error("Failure to associate loop device with open file")]
    AssociateWithOpenFile,
    #[error("Set Loop status exceeded number of retries ({0})")]
    StatusWriteBusy(usize),
    #[error("Set Loop status failed")]
    SetStatusFailed(#[from] nix::Error),
    #[error("Failure to set DIRECT I/O mode")]
    DirectIoModeFailed,
    #[error("Failure to dis-associate loop device from file descriptor")]
    ClearFailed,
}
