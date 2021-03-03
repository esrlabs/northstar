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

use super::Container;
use crate::api;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Application {0} is not started")]
    ApplicationNotStarted(Container),
    #[error("Application {0} is started")]
    ApplicationStarted(Container),
    #[error("Resource busy")]
    ResourceBusy,
    #[error("Missing resource {0}")]
    MissingResource(String),
    #[error("Application is already installed {0}")]
    ApplicationInstalled(Container),
    #[error("Unknown application {0}")]
    UnknownApplication(Container),
    #[error("Unknown repository {0}")]
    UnknownRepository(String),
    #[error("Unknown resource {0}")]
    UnknownResource(Container),

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
    #[error("Async runtime error: {0}")]
    AsyncRuntime(String),
}

impl From<Error> for api::model::Error {
    fn from(error: Error) -> api::model::Error {
        match error {
            Error::UnknownApplication(container) => {
                api::model::Error::UnknownApplication(container)
            }
            Error::ApplicationNotStarted(container) => {
                api::model::Error::ApplicationNotStarted(container)
            }
            Error::ApplicationStarted(container) => {
                api::model::Error::ApplicationRunning(container)
            }
            Error::ApplicationInstalled(container) => {
                api::model::Error::ApplicationInstalled(container)
            }
            Error::MissingResource(resource) => api::model::Error::MissingResource(resource),
            Error::UnknownRepository(id) => api::model::Error::UnknownRepository(id),
            Error::UnknownResource(container) => api::model::Error::UnknownResource(container),
            Error::Npk(error) => api::model::Error::Npk(error.to_string()),
            Error::Process(error) => api::model::Error::Process(error.to_string()),
            Error::Console(error) => api::model::Error::Console(error.to_string()),
            Error::Cgroups(error) => api::model::Error::Cgroups(error.to_string()),
            Error::Mount(error) => api::model::Error::Mount(error.to_string()),
            Error::Key(error) => api::model::Error::Key(error.to_string()),
            Error::Io(cause, error) => api::model::Error::Io(format!("{}: {}", cause, error)),
            Error::Os(cause, error) => api::model::Error::Os(format!("{}: {}", cause, error)),
            Error::AsyncRuntime(cause) => api::model::Error::AsyncRuntime(cause),
            Error::ResourceBusy => api::model::Error::ResourceBusy,
        }
    }
}
