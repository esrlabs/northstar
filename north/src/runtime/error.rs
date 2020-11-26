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

use crate::api;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("No application found")]
    ApplicationNotFound,
    #[error("Application is not running")]
    ApplicationNotRunning,
    #[error("Application {0} is running")]
    ApplicationRunning(String),
    #[error("Missing resource {0}")]
    MissingResource(String),
    #[error("Application {0} already installed")]
    ApplicationAlreadyInstalled(String),
    #[error("Resource {0} is already installed")]
    ResourceAlreadyInstalled(String),

    #[error("NPK: {0:?}")]
    Npk(npk::Error),
    #[error("Process: {0:?}")]
    Process(super::process::Error),
    #[error("Console: {0:?}")]
    Console(super::console::Error),
    #[error("Cgroups: {0}")]
    Cgroups(#[from] super::cgroups::Error),
    #[error("Mount: {0:?}")]
    Mount(super::mount::Error),
    #[error("Key: {0:?}")]
    Key(super::keys::Error),

    #[error("Io: {0}: {1:?}")]
    Io(String, io::Error),
    #[error("Os: {0}: {1:?}")]
    Os(String, nix::Error),
}

impl From<Error> for api::Error {
    fn from(error: Error) -> api::Error {
        match error {
            Error::ApplicationNotFound => api::Error::ApplicationNotFound,
            Error::ApplicationNotRunning => api::Error::ApplicationNotRunning,
            Error::ApplicationRunning(name) => api::Error::ApplicationRunning(name),
            Error::MissingResource(resource) => api::Error::MissingResource(resource),
            Error::ApplicationAlreadyInstalled(name) => {
                api::Error::ApplicationAlreadyInstalled(name)
            }
            Error::ResourceAlreadyInstalled(resource) => {
                api::Error::ResourceAlreadyInstalled(resource)
            }
            Error::Npk(error) => api::Error::Npk(error.to_string()),
            Error::Process(error) => api::Error::Process(error.to_string()),
            Error::Console(error) => api::Error::Console(error.to_string()),
            Error::Cgroups(error) => api::Error::Cgroups(error.to_string()),
            Error::Mount(error) => api::Error::Mount(error.to_string()),
            Error::Key(error) => api::Error::Key(error.to_string()),
            Error::Io(cause, error) => api::Error::Io(format!("{}: {}", cause, error)),
            Error::Os(cause, error) => api::Error::Os(format!("{}: {}", cause, error)),
        }
    }
}
