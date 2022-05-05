use thiserror::Error;

use crate::{
    api::{self},
    common::name::Name,
    npk,
    runtime::{Container, ExitStatus, RepositoryId},
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    Configuration(String),
    #[error("invalid container {0}")]
    InvalidContainer(Container),
    #[error("invalid arguments {0}")]
    InvalidArguments(String),
    #[error("container {0} cannot be mounted: busy")]
    MountBusy(Container),
    #[error("duplicate container {0}")]
    DuplicateContainer(Container),
    #[error("container {0} cannot be unmounted: busy")]
    UmountBusy(Container),
    #[error("container {0} failed to start: already started")]
    StartContainerStarted(Container),
    #[error("container {0} failed to start: resources failed to mount")]
    StartContainerResource(Container),
    #[error("container {0} failed to start: resource {1} version {2} is missing")]
    StartContainerMissingResource(Container, Name, String),
    #[error("container {0} failed to start: {1}")]
    StartContainerFailed(Container, String),
    #[error("container {0} failed to stop")]
    StopContainerNotStarted(Container),
    #[error("container {0} failed is stop: not started")]
    ContainerNotStarted(Container),
    #[error("invalid repository {0}")]
    InvalidRepository(RepositoryId),
    #[error("failed to install {0}: already installed")]
    InstallDuplicate(Container),
    #[error("critical container failure")]
    CriticalContainer(Container, ExitStatus),

    #[error("npk {0:?}: {1:?}")]
    Npk(String, npk::npk::Error),
    #[error("console: {0:?}")]
    Console(super::console::Error),
    #[error("cgroups: {0}")]
    Cgroups(#[from] super::cgroups::Error),
    #[error("mount: {0}")]
    Mount(super::mount::Error),
    #[error("name: {0}")]
    Name(String),
    #[error("key: {0}")]
    Key(super::key::Error),

    #[error("{0}")]
    Unexpected(String, #[source] Box<dyn std::error::Error + Sync + Send>),
}

/// Similar anyhow's Context trait
pub(crate) trait Context<T> {
    /// Adds a contextual message to the result's error
    fn context<C: ToString>(self, context: C) -> Result<T, Error>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> Context<T> for Result<T, E> {
    fn context<C: ToString>(self, context: C) -> Result<T, Error> {
        self.map_err(|e| Error::Unexpected(context.to_string(), Box::new(e)))
    }
}

impl From<Error> for api::model::Error {
    fn from(error: Error) -> api::model::Error {
        match error {
            Error::Configuration(context) => api::model::Error::Configuration { context },
            Error::DuplicateContainer(container) => {
                api::model::Error::DuplicateContainer { container }
            }
            Error::InvalidContainer(container) => api::model::Error::InvalidContainer { container },
            Error::InvalidArguments(cause) => api::model::Error::InvalidArguments { cause },
            Error::MountBusy(container) => api::model::Error::MountBusy { container },
            Error::UmountBusy(container) => api::model::Error::UmountBusy { container },
            Error::StartContainerStarted(container) => {
                api::model::Error::StartContainerStarted { container }
            }
            Error::StartContainerResource(container) => {
                api::model::Error::StartContainerResource { container }
            }
            Error::StartContainerMissingResource(container, resource, version) => {
                api::model::Error::StartContainerMissingResource {
                    container,
                    resource,
                    version,
                }
            }
            Error::StartContainerFailed(container, error) => {
                api::model::Error::StartContainerFailed { container, error }
            }
            Error::StopContainerNotStarted(container) => {
                api::model::Error::StopContainerNotStarted { container }
            }
            Error::ContainerNotStarted(container) => {
                api::model::Error::StopContainerNotStarted { container }
            }
            Error::InvalidRepository(repository) => {
                api::model::Error::InvalidRepository { repository }
            }
            Error::InstallDuplicate(container) => api::model::Error::InstallDuplicate { container },
            Error::CriticalContainer(container, status) => api::model::Error::CriticalContainer {
                container,
                status: status.into(),
            },
            Error::Npk(cause, error) => api::model::Error::Unexpected {
                module: "Npk".into(),
                error: format!("{}: {}", cause, error),
            },
            Error::Console(error) => api::model::Error::Unexpected {
                module: "Console".into(),
                error: error.to_string(),
            },
            Error::Cgroups(error) => api::model::Error::Unexpected {
                module: "CGroups".into(),
                error: error.to_string(),
            },
            Error::Mount(error) => api::model::Error::Unexpected {
                module: "Mount".into(),
                error: error.to_string(),
            },
            Error::Name(error) => api::model::Error::Unexpected {
                module: "Name".into(),
                error,
            },
            Error::Key(error) => api::model::Error::Unexpected {
                module: "Key".into(),
                error: error.to_string(),
            },
            Error::Unexpected(module, error) => api::model::Error::Unexpected {
                module,
                error: error.to_string(),
            },
        }
    }
}
