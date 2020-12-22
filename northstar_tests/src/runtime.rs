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

//! Controls Northstar runtime instances

use crate::process_assert::ProcessAssert;
use color_eyre::eyre::{eyre, Error, Result, WrapErr};
use northstar::{api, runtime, runtime::config::Config};
use std::{fs, path::Path};
use tokio::{time, time::timeout};

const TIMEOUT: time::Duration = time::Duration::from_secs(3);

/// A running instance of northstar.
pub struct Runtime(runtime::Runtime);

impl Runtime {
    /// Launches an instance of northstar
    pub async fn launch() -> Result<Runtime, Error> {
        let config = toml::from_str::<Config>(
            &fs::read_to_string("northstar.toml").wrap_err("Failed to read northstar.toml")?,
        )
        .wrap_err("Failed to parse northstar.toml")?;
        let runtime = timeout(TIMEOUT, runtime::Runtime::start(config))
            .await
            .wrap_err("Launching northstar timed out")
            .and_then(|result| result.wrap_err("Failed to instantiate northstar runtime"))?;
        Ok(Runtime(runtime))
    }

    pub async fn launch_with_config(config: runtime::config::Config) -> Result<Runtime, Error> {
        let runtime = timeout(TIMEOUT, runtime::Runtime::start(config))
            .await
            .wrap_err("Launching northstar timed out")
            .and_then(|result| result.wrap_err("Failed to instantiate northstar runtime"))?;
        Ok(Runtime(runtime))
    }

    pub async fn start(&mut self, name: &str) -> Result<Option<ProcessAssert>> {
        timeout(
            TIMEOUT,
            self.0.request(api::Request::Start(name.to_string())),
        )
        .await
        .wrap_err("Starting container timed out")
        .and_then(|result| result.wrap_err("Failed to start container"))?;

        let response = timeout(TIMEOUT, self.0.request(api::Request::Containers))
            .await
            .wrap_err("Getting containers status timed out")
            .and_then(|result| result.wrap_err("Failed to get container status"))?;

        match response {
            api::Response::Containers(containers) => {
                let process = containers
                    .into_iter()
                    .filter(|c| c.manifest.name == name)
                    .filter_map(|c| c.process.map(|p| p.pid))
                    .next()
                    .map(|pid| ProcessAssert::new(pid as u64));
                Ok(process)
            }
            _ => unreachable!(),
        }
    }

    pub async fn stop(&mut self, name: &str) -> Result<()> {
        timeout(
            TIMEOUT,
            self.0.request(api::Request::Stop(name.to_string())),
        )
        .await
        .wrap_err("Stopping container timed out")
        .and_then(|result| result.wrap_err("Failed to stop container"))?;
        Ok(())
    }

    pub async fn install(&mut self, repo: &str, npk: &Path) -> Result<()> {
        let response = timeout(TIMEOUT, self.0.install(repo, npk))
            .await
            .wrap_err("Installing container timed out")
            .and_then(|result| result.wrap_err("Failed to install container"))
            .map_err(|e| eyre!("API error: {:?}", e))?;

        match response {
            api::Response::Ok(())
            | api::Response::Err(api::Error::ContainerAlreadyInstalled(_)) => Ok(()),
            api::Response::Err(e) => Err(eyre!("Install container response: {:?}", e)),
            _ => unreachable!(),
        }
    }

    pub async fn uninstall(&mut self, name: &str, version: &str) -> Result<()> {
        let uninstall = api::Request::Uninstall {
            name: name.to_string(),
            version: npk::manifest::Version::parse(version)?,
        };
        timeout(TIMEOUT, self.0.request(uninstall))
            .await
            .wrap_err("Uninstalling container timed out")
            .and_then(|result| result.wrap_err("Failed to uninstall container"))?;
        Ok(())
    }

    pub async fn shutdown(self) -> Result<()> {
        timeout(TIMEOUT, self.0.stop_wait())
            .await
            .wrap_err("Shutting down runtime timed out")
            .and_then(|result| result.wrap_err("Failed to shutdown runtime"))?;
        Ok(())
    }
}
