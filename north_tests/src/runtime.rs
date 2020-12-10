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

//! Controls North runtime instances

use color_eyre::eyre::{eyre, Result, WrapErr};
use north::{api, runtime};
use std::{future::Future, path::Path};
use tokio::{time, time::timeout};

const TIMEOUT: time::Duration = time::Duration::from_secs(3);

/// A running instance of north.
pub struct Runtime(runtime::Runtime);

#[must_use = "Shoud be checked for expected response"]
pub struct ApiResponse(Result<api::Response>);

impl ApiResponse {
    pub fn expect_ok(self) -> Result<()> {
        match self.0 {
            Ok(api::Response::Ok(())) => Ok(()),
            _ => Err(eyre!("Response is not ok")),
        }
    }

    pub fn expect_err(self, err: api::Error) -> Result<()> {
        match self.0 {
            Ok(api::Response::Err(e)) if err == e => Ok(()),
            _ => Err(eyre!("Response is not an error")),
        }
    }

    pub fn could_fail(self) {}
}

pub fn timeout_on<R>(f: impl Future<Output = R>) -> Result<R> {
    futures::executor::block_on(timeout(TIMEOUT, f)).wrap_err("Future timed out")
}

impl Runtime {
    /// Launches an instance of north
    pub fn launch(config: runtime::config::Config) -> Runtime {
        let runtime = timeout_on(runtime::Runtime::start(config))
            .and_then(|result| result.wrap_err("Failed to instantiate north runtime"))
            .expect("Failed to launch north runtime");
        Runtime(runtime)
    }

    pub fn start(&mut self, name: &str) -> ApiResponse {
        let response = timeout_on(self.0.request(api::Request::Start(name.to_string())))
            .and_then(|result| result.wrap_err("Failed to start container"));
        ApiResponse(response)
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

    pub fn stop(&mut self, name: &str) -> ApiResponse {
        let response = timeout_on(self.0.request(api::Request::Stop(name.to_string())))
            .and_then(|result| result.wrap_err("Failed to stop container"));
        ApiResponse(response)
    }

    pub fn install(&mut self, npk: &Path) -> ApiResponse {
        let response = timeout_on(self.0.install(npk))
            .and_then(|result| result.wrap_err("Failed to install container"));
        ApiResponse(response)
    }

    pub fn uninstall(&mut self, name: &str, version: &str) -> ApiResponse {
        let uninstall = api::Request::Uninstall {
            name: name.to_string(),
            version: npk::manifest::Version::parse(version).expect("Failed to parse version"),
        };

        let response = timeout_on(self.0.request(uninstall))
            .and_then(|result| result.wrap_err("Failed to uninstall container"));
        ApiResponse(response)
    }

    pub fn shutdown(self) -> Result<()> {
        timeout_on(self.0.stop_wait())
            .and_then(|result| result.wrap_err("Failed to shutdown runtime"))
            .map(|_| ())
    }
}
