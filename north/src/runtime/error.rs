use crate::runtime::{InstallationResult, Name};
use anyhow::Error as AnyhowError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("No application found")]
    UnknownApplication,
    #[error("Missing resouce {0}")]
    MissingResource(String),
    #[error("Failed to spawn process: {0}")]
    ProcessError(AnyhowError),
    #[error("Application(s) \"{0:?}\" is/are running")]
    ApplicationRunning(Vec<Name>),
    // #[error("Failed to uninstall")]
    // UninstallationError(AnyhowError),
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
    #[error("Failure to mount: {0}")]
    MountError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
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
                InstallationResult::DeviceMapperProblem(format!("{}", e))
            }
            InstallFailure::LoopDeviceError(e) => {
                InstallationResult::LoopDeviceError(format!("{}", e))
            }
            InstallFailure::HashInvalid(s) => InstallationResult::HashInvalid(s),
            InstallFailure::KeyNotFound(s) => InstallationResult::KeyNotFound(s),
            InstallFailure::ApplicationAlreadyInstalled(_) => {
                InstallationResult::ApplicationAlreadyInstalled
            }
            InstallFailure::InternalError(s) => InstallationResult::InternalError(s),
            InstallFailure::MountError(s) => InstallationResult::MountError(s),
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
    OpenDmError,
    #[error("Failure issuing an IO-CTL call")]
    IoCtrlError,
    #[error("Response DM buffer requires too much space")]
    BufferFull,
    #[error("Could not create device")]
    CreateDeviceFailed,
    #[error("Failure to remove device")]
    DeviceRemovalFailed,
    #[error("Failure to suspend device")]
    SuspendDeviceError,
}

#[derive(Error, Debug)]
pub enum LoopDeviceError {
    #[error("Control file for loop device could not be created")]
    ControlFileError,
    #[error("Failure to find or allocate free loop device")]
    NoFreeDeviceFound,
    #[error("Failure adding new loop device")]
    DeviceAlreadyAllocated,
    #[error("Failure to associate loop device with open file")]
    AssociateError,
    #[error("Set Loop status exceeded number of retries ({0})")]
    StatusWriteBusy(usize),
    #[error("Set Loop status failed")]
    SetStatusError,
    #[error("Failure to set DIRECT I/O mode")]
    DirectIoError,
    #[error("Failure to dis-associate loop device from file descriptor")]
    ClearError,
}
