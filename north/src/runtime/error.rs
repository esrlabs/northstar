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
use super::linux::device_mapper;
#[cfg(any(target_os = "android", target_os = "linux"))]
use super::linux::loopdev;
use super::{InstallationResult, Name};
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("No application found")]
    ApplicationNotFound,
    #[error("Missing resouce {0}")]
    MissingResource(String),
    #[error("Problem with handling process: {0}")]
    ProcessError(ProcessError),
    #[error("Application(s) \"{0:?}\" is/are running")]
    ApplicationRunning(Vec<Name>),
    #[error("Failed to install")]
    InstallationError(InstallFailure),
    #[error("Failed to uninstall")]
    UninstallationError(InstallFailure),
    #[error("Application is not running")]
    ApplicationNotRunning,
    #[error("Problem with cgroups")]
    CGroupProblem(CGroupError),
    #[error("Problem with keys: {0}")]
    KeyError(super::keys::Error),
    #[error("OS level problem: {context}")]
    OsProblem {
        context: String,
        #[source]
        error: nix::Error,
    },
    #[error("Io problem: {context}")]
    GeneralIoProblem {
        context: String,
        #[source]
        error: io::Error,
    },
    #[error("Error with communication protocol: {0}")]
    ProtocolError(String),
    #[error("Configuration of runtime incorrect: {0}")]
    ConfigurationError(String),
}

#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("Problem starting the process: {0}")]
    StartupError(String),
    #[error("Problem with stopping the process")]
    StopProblem,
    #[error("Wrong container type: {0}")]
    WrongContainerType(String),
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[error("Problem creating a minijail: {0}")]
    MinijailProblem(#[from] minijail::Error),
    #[error("IO problem: {context}")]
    IoProblem {
        context: String,
        #[source]
        error: io::Error,
    },
    #[error("Linux problem: {context}")]
    LinuxProblem {
        context: String,
        #[source]
        error: nix::Error,
    },
}

#[derive(Error, Debug)]
pub enum CGroupError {
    #[error("No such cgroup found: {0}")]
    CGroupNotFound(String),
    #[error("Problem destroying cgroug: {context}")]
    DestroyError {
        context: String,
        #[source]
        error: io::Error,
    },
    #[error("Problem mounting cgroup: {context}")]
    MountProblem {
        context: String,
        #[source]
        error: Option<io::Error>,
    },
    #[error("File problem cgroup: {context}")]
    FileProblem {
        context: String,
        #[source]
        error: io::Error,
    },
}

#[derive(Error, Debug)]
pub enum InstallFailure {
    #[error("File seems to be corrupted")]
    FileCorrupted(#[from] zip::result::ZipError),
    #[error("Signature file invalid ({0})")]
    SignatureFileInvalid(String),
    #[error("Signature malformed")]
    MalformedSignature,
    #[error("Hashes malformed ({0})")]
    MalformedHashes(String),
    #[error("Problem verifiing the manifest ({0})")]
    MalformedManifest(String),
    #[error("Problem verifiing content with signature ({0})")]
    SignatureVerificationFailed(String),
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
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[error("Problem with device mapper")]
    DeviceMapper(device_mapper::Error),
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[error("Problem with loop device")]
    LoopDeviceError(loopdev::Error),
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
    #[error("Failure to mount: {context}")]
    INotifyError {
        context: String,
        #[source]
        error: nix::Error,
    },
    #[error("Problem with file system: {context}")]
    FileIoProblem {
        context: String,
        #[source]
        error: io::Error,
    },
    #[error("Timeout error: {0}")]
    TimeoutError(String),
}

impl From<InstallFailure> for InstallationResult {
    fn from(failure: InstallFailure) -> InstallationResult {
        match failure {
            InstallFailure::FileCorrupted(_) => InstallationResult::FileCorrupted,
            InstallFailure::SignatureFileInvalid(_) => InstallationResult::SignatureFileInvalid,
            InstallFailure::MalformedSignature => InstallationResult::MalformedSignature,
            InstallFailure::MalformedHashes(_) => InstallationResult::MalformedHashes,
            InstallFailure::MalformedManifest(s) => InstallationResult::MalformedManifest(s),
            InstallFailure::VerityProblem(s) => InstallationResult::VerityProblem(s),
            InstallFailure::ArchiveError(s) => InstallationResult::ArchiveError(s),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            InstallFailure::DeviceMapper(e) => {
                InstallationResult::DeviceMapperProblem(format!("{:?}", e))
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            InstallFailure::LoopDeviceError(e) => {
                InstallationResult::LoopDeviceError(format!("{}", e))
            }
            InstallFailure::HashInvalid(s) => InstallationResult::HashInvalid(s),
            InstallFailure::KeyNotFound(s) => InstallationResult::KeyNotFound(s),
            InstallFailure::ApplicationAlreadyInstalled(_) => {
                InstallationResult::ApplicationAlreadyInstalled
            }
            InstallFailure::FileIoProblem { context, error: _ } => {
                InstallationResult::FileIoProblem(context)
            }
            InstallFailure::MountError { context, error: _ } => {
                InstallationResult::MountError(context)
            }
            InstallFailure::INotifyError { context, error: _ } => {
                InstallationResult::INotifyError(context)
            }
            InstallFailure::TimeoutError(s) => InstallationResult::TimeoutError(s),
            InstallFailure::NoVerityHeader => {
                InstallationResult::VerityProblem("Verity header missing".to_string())
            }
            InstallFailure::UnexpectedVerityAlgorithm(s) => {
                InstallationResult::VerityProblem(format!("Unexpected verity algorithm: {}", s))
            }
            InstallFailure::UnexpectedVerityVersion(n) => {
                InstallationResult::VerityProblem(format!("Unexpected verity version: {}", n))
            }
            InstallFailure::SignatureVerificationFailed(s) => {
                InstallationResult::SignatureVerificationFailed(s)
            }
        }
    }
}
