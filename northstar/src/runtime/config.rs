// Copyright (c) 2019 - 2021 ESRLabs
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

use super::{Error, RepositoryId};
use crate::{common::non_null_string::NonNullString, util::is_rw};
use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf};
use url::Url;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Console address.
    pub console: Option<Url>,
    /// Directory with unpacked containers.
    pub run_dir: PathBuf,
    /// Directory where rw data of container shall be stored
    pub data_dir: PathBuf,
    /// Directory for logfile
    pub log_dir: PathBuf,
    /// Top level cgroup name
    pub cgroup: NonNullString,
    /// Repositories
    pub repositories: HashMap<RepositoryId, Repository>,
    /// Debugging options
    pub debug: Option<Debug>,
}

/// Repository type
#[derive(Clone, Debug, Deserialize)]
pub enum RepositoryType {
    /// Directory based
    #[serde(rename = "fs")]
    Fs { dir: PathBuf },
    /// Memory based
    #[serde(rename = "mem")]
    Memory,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Repository {
    /// Optional key for this repository
    pub key: Option<PathBuf>,
    /// Repository type: fs or mem
    pub r#type: RepositoryType,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Debug {
    /// Strace options
    pub strace: Option<debug::Strace>,
    /// perf options
    pub perf: Option<debug::Perf>,
}

pub mod debug {
    use serde::Deserialize;
    use std::path::PathBuf;

    #[derive(Clone, Debug, Deserialize)]
    #[serde(rename_all(deserialize = "snake_case"))]
    pub enum StraceOutput {
        /// Log to a file in log_dir
        File,
        /// Log the runtimes logging system
        Log,
    }

    /// Strace debug options
    #[derive(Clone, Debug, Deserialize)]
    pub struct Strace {
        /// Log to a file in log_dir
        pub output: StraceOutput,
        /// Path to the strace binary
        pub path: Option<PathBuf>,
        /// Additional strace command line flags options
        pub flags: Option<String>,
        /// Include strace output before final execve
        pub include_runtime: Option<bool>,
    }

    /// perf profiling options
    #[derive(Clone, Debug, Deserialize)]
    pub struct Perf {
        /// Path to the perf binary
        pub path: Option<PathBuf>,
        /// Optional additional flags
        pub flags: Option<String>,
    }
}

impl Config {
    /// Validate the configuration
    pub(crate) async fn check(&self) -> Result<(), Error> {
        // Check run_dir for existence and rw
        if !self.run_dir.exists() {
            return Err(Error::Configuration(format!(
                "Configured run_dir {} does not exist",
                self.run_dir.display()
            )));
        } else if !is_rw(&self.run_dir).await {
            return Err(Error::Configuration(format!(
                "Configured run_dir {} is not read and/or writeable",
                self.run_dir.display()
            )));
        }

        // Check data_dir for existence and rw
        if !self.data_dir.exists() {
            return Err(Error::Configuration(format!(
                "Configured data_dir {} does not exist",
                self.data_dir.display()
            )));
        } else if !is_rw(&self.data_dir).await {
            return Err(Error::Configuration(format!(
                "Configured data_dir {} is not read and/or writeable",
                self.data_dir.display()
            )));
        }

        // Check log_dir for existence and rw
        if !self.log_dir.exists() {
            return Err(Error::Configuration(format!(
                "Configured data_dir {} does not exist",
                self.log_dir.display()
            )));
        } else if !is_rw(&self.log_dir).await {
            return Err(Error::Configuration(format!(
                "Configured log_dir {} is not read and/or writeable",
                self.log_dir.display()
            )));
        }

        Ok(())
    }
}
