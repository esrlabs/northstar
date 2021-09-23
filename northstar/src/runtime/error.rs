use std::io;

use thiserror::Error;

use crate::{
    api, npk,
    runtime::{repository::RepositoryId, Container, ExitStatus},
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid configuration: {0}")]
    Configuration(String),
    #[error("Invalid container {0}")]
    InvalidContainer(Container),
    #[error("Invalid arguments {0}")]
    InvalidArguments(String),
    #[error("Container {0} cannot be mounted because it is already mounted")]
    MountBusy(Container),
    #[error("Duplicate container {0}")]
    DuplicateContainer(Container),
    #[error("Container {0} cannot be unmounted: busy")]
    UmountBusy(Container),
    #[error("Container {0} failed to start: Already started")]
    StartContainerStarted(Container),
    #[error("Container {0} failed to start: Resources cannot be started")]
    StartContainerResource(Container),
    #[error("Container {0} failed to start: Resource {1} is missing")]
    StartContainerMissingResource(Container, Container),
    #[error("Container {0} failed to start: {1}")]
    StartContainerFailed(Container, String),
    #[error("Container {0} failed to stop: Not started")]
    StopContainerNotStarted(Container),
    #[error("Invalid repository {0}")]
    InvalidRepository(RepositoryId),
    #[error("Failed to install {0}: Already installed")]
    InstallDuplicate(Container),
    #[error("Critical container failure")]
    CriticalContainer(Container, ExitStatus),

    #[error("NPK {0:?}: {1:?}")]
    Npk(String, npk::npk::Error),
    #[error("Console: {0:?}")]
    Console(super::console::Error),
    #[error("Cgroups: {0}")]
    Cgroups(#[from] super::cgroups::Error),
    #[error("Mount: {0}")]
    Mount(super::mount::Error),
    #[error("Name: {0}")]
    Name(String),
    #[error("Key: {0}")]
    Key(super::key::Error),

    #[error("Io: {0}: {1:?}")]
    Io(String, io::Error),
    #[error("Os: {0}: {1:?}")]
    Os(String, nix::Error),

    #[error("{0}: {1:?}")]
    Other(String, String),
}

impl Error {
    pub(crate) fn io<T: ToString>(m: T, e: io::Error) -> Error {
        Error::Io(m.to_string(), e)
    }

    pub(crate) fn os<T: ToString>(e: T, err: nix::Error) -> Error {
        Error::Os(e.to_string(), err)
    }

    pub(crate) fn other<T: ToString, E: std::fmt::Debug>(e: T, err: E) -> Error {
        Error::Other(e.to_string(), format!("{:?}", err))
    }
}

impl From<Error> for api::model::Error {
    fn from(error: Error) -> api::model::Error {
        match error {
            Error::Configuration(cause) => api::model::Error::Configuration(cause),
            Error::DuplicateContainer(container) => {
                api::model::Error::DuplicateContainer(container)
            }
            Error::InvalidContainer(container) => api::model::Error::InvalidContainer(container),
            Error::InvalidArguments(cause) => api::model::Error::InvalidArguments(cause),
            Error::MountBusy(container) => api::model::Error::MountBusy(container),
            Error::UmountBusy(container) => api::model::Error::UmountBusy(container),
            Error::StartContainerStarted(container) => {
                api::model::Error::StartContainerStarted(container)
            }
            Error::StartContainerResource(container) => {
                api::model::Error::StartContainerResource(container)
            }
            Error::StartContainerMissingResource(container, resource) => {
                api::model::Error::StartContainerMissingResource(container, resource)
            }
            Error::StartContainerFailed(container, reason) => {
                api::model::Error::StartContainerFailed(container, reason)
            }
            Error::StopContainerNotStarted(container) => {
                api::model::Error::StopContainerNotStarted(container)
            }
            Error::InvalidRepository(repository) => {
                api::model::Error::InvalidRepository(repository.to_string())
            }
            Error::InstallDuplicate(container) => api::model::Error::InstallDuplicate(container),
            Error::CriticalContainer(container, status) => {
                api::model::Error::CriticalContainer(container, status.into())
            }
            Error::Npk(cause, error) => api::model::Error::Npk(cause, error.to_string()),
            Error::Console(error) => api::model::Error::Console(error.to_string()),
            Error::Cgroups(error) => api::model::Error::Cgroups(error.to_string()),
            Error::Mount(error) => api::model::Error::Mount(error.to_string()),
            Error::Name(error) => api::model::Error::Name(error),
            Error::Key(error) => api::model::Error::Key(error.to_string()),
            Error::Io(cause, error) => api::model::Error::Io(format!("{}: {}", cause, error)),
            Error::Os(cause, error) => api::model::Error::Os(format!("{}: {}", cause, error)),
            Error::Other(cause, error) => api::model::Error::Other(cause, error),
        }
    }
}
