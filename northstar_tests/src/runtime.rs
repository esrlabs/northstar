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

use color_eyre::eyre::{eyre, Result, WrapErr};
use north::{api, runtime};
use std::path::Path;
use tokio::{time, time::timeout};

const TIMEOUT: time::Duration = time::Duration::from_secs(3);

/// A running instance of northstar.
pub struct Runtime(runtime::Runtime);

#[must_use = "Shoud be checked for expected response"]
pub struct ApiResponse(api::Response);

impl From<api::Response> for ApiResponse {
    fn from(response: api::Response) -> Self {
        ApiResponse(response)
    }
}

impl ApiResponse {
    pub fn expect_ok(self) -> Result<()> {
        match self.0 {
            api::Response::Ok(()) => Ok(()),
            _ => Err(eyre!("Response is not ok")),
        }
    }

    pub fn expect_err(self, err: api::Error) -> Result<()> {
        match self.0 {
            api::Response::Err(e) if err == e => Ok(()),
            _ => Err(eyre!("Response is not an error")),
        }
    }

    pub fn could_fail(self) {}
}

impl Runtime {
    /// Launches an instance of north
    pub async fn launch(config: runtime::config::Config) -> Result<Runtime> {
        let runtime = timeout(TIMEOUT, runtime::Runtime::start(config))
            .await
            .wrap_err("Launching northstar timed out")
            .and_then(|result| result.wrap_err("Failed to instantiate northstar runtime"))?;
        Ok(Runtime(runtime))
    }

    pub async fn start(&mut self, name: &str) -> Result<ApiResponse> {
        timeout(
            TIMEOUT,
            self.0.request(api::Request::Start(name.to_string())),
        )
        .await
        .wrap_err("Starting container timed out")
        .and_then(|result| result.wrap_err("Failed to start container"))
        .map(ApiResponse::from)
    }

    pub async fn pid(&mut self, name: &str) -> Result<u32> {
        let response = timeout(TIMEOUT, self.0.request(api::Request::Containers))
            .await
            .wrap_err("Getting containers status timed out")
            .and_then(|result| result.wrap_err("Failed to get container status"))?;

        match response {
            api::Response::Containers(containers) => containers
                .into_iter()
                .filter(|c| c.manifest.name == name)
                .filter_map(|c| c.process.map(|p| p.pid))
                .next()
                .ok_or_else(|| eyre!("Failed to find PID")),
            api::Response::Err(e) => Err(eyre!("Failed to request containers: {:?}", e)),
            _ => unreachable!(),
        }
    }

    pub async fn stop(&mut self, name: &str) -> Result<ApiResponse> {
        timeout(
            TIMEOUT,
            self.0.request(api::Request::Stop(name.to_string())),
        )
        .await
        .wrap_err("Stopping container timed out")
        .and_then(|result| result.wrap_err("Failed to stop container"))
        .map(ApiResponse::from)
    }

    pub async fn install(&mut self, npk: &Path) -> Result<ApiResponse> {
        timeout(TIMEOUT, self.0.install(npk))
            .await
            .wrap_err("Installing container timed out")
            .and_then(|result| result.wrap_err("Failed to install container"))
            .map(ApiResponse::from)
    }

    pub async fn uninstall(&mut self, name: &str, version: &str) -> Result<ApiResponse> {
        let uninstall = api::Request::Uninstall {
            name: name.to_string(),
            version: npk::manifest::Version::parse(version)?,
        };

        timeout(TIMEOUT, self.0.request(uninstall))
            .await
            .wrap_err("Uninstalling container timed out")
            .and_then(|result| result.wrap_err("Failed to uninstall container"))
            .map(ApiResponse::from)
    }

    pub async fn shutdown(self) -> Result<()> {
        timeout(TIMEOUT, self.0.stop_wait())
            .await
            .wrap_err("Shutting down runtime timed out")
            .and_then(|result| result.wrap_err("Failed to shutdown runtime"))?;
        Ok(())
    }
}
