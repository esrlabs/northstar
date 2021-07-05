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

use super::{Container, ExitStatus, RepositoryId};
use crate::api::{self};
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid configuration: {0}")]
    Configuration(String),
    #[error("Invalid container {0}")]
    InvalidContainer(Container),
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
}

impl Error {
    pub(crate) fn io<T: ToString>(m: T, e: io::Error) -> Error {
        Error::Io(m.to_string(), e)
    }

    pub(crate) fn os<T: ToString>(e: T, err: nix::Error) -> Error {
        Error::Os(e.to_string(), err)
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
                api::model::Error::InvalidRepository(repository)
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
        }
    }
}
