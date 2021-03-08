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

use super::{Container, RepositoryId};
use crate::api;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    /// The container is not known to the system
    #[error("Invalid container {0}")]
    InvalidContainer(Container),
    /// The container cannot be started because it's already running
    #[error("Container {0} cannot be umounted: busy")]
    UmountBusy(Container),
    /// The container cannot be started because it's already running
    #[error("Container {0} failed to start: Already started")]
    StartContainerStarted(Container),
    /// The container cannot be started because it's already running
    #[error("Container {0} failed to start: Resources cannot be started")]
    StartContainerResource(Container),
    /// The container cannot be started because it's already running
    #[error("Container {0} failed to start: Resource {1} is missing")]
    StartContainerMissingResource(Container, Container),
    /// The container cannot be started because it's already running
    #[error("Container {0} failed to stop: Not started")]
    StopContainerNotStarted(Container),
    /// The container is not known to the system
    #[error("Invalid repository {0}")]
    InvalidRepository(RepositoryId),
    /// The container is not known to the system
    #[error("Failed to install {0}: Already installed")]
    InstallDuplicate(Container),

    #[error("NPK error: {0:?}")]
    Npk(npk::npk::Error),
    #[error("Process: {0:?}")]
    Process(super::process::Error),
    #[error("Console: {0:?}")]
    Console(super::console::Error),
    #[error("Cgroups: {0}")]
    Cgroups(#[from] super::cgroups::Error),
    #[error("Mount: {0}")]
    Mount(super::mount::Error),
    #[error("Key: {0}")]
    Key(super::key::Error),

    #[error("Io: {0}: {1:?}")]
    Io(String, io::Error),
    #[error("Os: {0}: {1:?}")]
    Os(String, nix::Error),
}

impl From<Error> for api::model::Error {
    fn from(error: Error) -> api::model::Error {
        match error {
            Error::InvalidContainer(container) => api::model::Error::InvalidContainer(container),
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
            Error::StopContainerNotStarted(container) => {
                api::model::Error::StopContainerNotStarted(container)
            }
            Error::InvalidRepository(repository) => {
                api::model::Error::InvalidRepository(repository)
            }
            Error::InstallDuplicate(container) => api::model::Error::InstallDuplicate(container),
            Error::Npk(error) => api::model::Error::Npk(error.to_string()),
            Error::Process(error) => api::model::Error::Process(error.to_string()),
            Error::Console(error) => api::model::Error::Console(error.to_string()),
            Error::Cgroups(error) => api::model::Error::Cgroups(error.to_string()),
            Error::Mount(error) => api::model::Error::Mount(error.to_string()),
            Error::Key(error) => api::model::Error::Key(error.to_string()),
            Error::Io(cause, error) => api::model::Error::Io(format!("{}: {}", cause, error)),
            Error::Os(cause, error) => api::model::Error::Os(format!("{}: {}", cause, error)),
        }
    }
}
