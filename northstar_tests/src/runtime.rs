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
use nix::mount::MsFlags;
use northstar::{
    api,
    runtime::{self},
};
use std::{
    future::Future,
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use tokio::{fs, time, time::timeout};
use tokio_util::sync::CancellationToken;

pub use northstar::runtime::config::{Config, Repository};

/// Returns the default northstar config
pub async fn default_config() -> Result<Config> {
    let config_string = fs::read_to_string("northstar.toml")
        .await
        .wrap_err("Failed to read northstar.toml")?;
    toml::from_str::<Config>(&config_string).wrap_err("Failed to parse northstar.toml")
}

const TIMEOUT: time::Duration = time::Duration::from_secs(3);

#[must_use = "Shoud be checked for expected response"]
pub struct ApiResponse(pub Result<api::model::Response>);

impl ApiResponse {
    pub fn expect_ok(self) -> Result<()> {
        match self.0 {
            Ok(api::model::Response::Ok(())) => Ok(()),
            _ => Err(eyre!("Response is not ok")),
        }
    }

    pub fn expect_err(self, err: api::model::Error) -> Result<()> {
        match self.0 {
            Ok(api::model::Response::Err(e)) if err == e => Ok(()),
            _ => Err(eyre!("Response is not an error")),
        }
    }

    pub fn could_fail(self) {}
}

pub fn timeout_on<R>(f: impl Future<Output = R>) -> Result<R> {
    futures::executor::block_on(timeout(TIMEOUT, f)).wrap_err("Future timed out")
}

/// A running instance of northstar.
pub struct Runtime {
    runtime: Option<runtime::Runtime>,
    stop: CancellationToken,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(r) = self.runtime.take() {
            futures::executor::block_on(timeout(TIMEOUT, r.wait()))
                .expect("Failed to wait for runtime termination")
                .expect("Failed shutdown")
        }
    }
}

impl Runtime {
    /// Launches an instance of north
    pub async fn launch() -> Result<Runtime> {
        Runtime::launch_with_config(default_config().await?).await
    }

    /// Launches an instance of north with the specified configuration
    pub async fn launch_with_config(mut config: Config) -> Result<Runtime> {
        // It is expected that the "default" repository contains the example containers
        let default_repository = &mut config
            .repositories
            .get_mut("default")
            .ok_or_else(|| eyre!("No \"default\" repository in configuration"))?
            .dir;

        // Discard changes to the default repository at the end of the test
        *default_repository =
            tokio::task::block_in_place(|| overlay_directory(default_repository))?;

        let (runtime, stop) = timeout(TIMEOUT, runtime::Runtime::start(config))
            .await
            .wrap_err("Launching northstar timed out")
            .and_then(|result| result.wrap_err("Failed to instantiate northstar runtime"))?;
        Ok(Runtime {
            runtime: Some(runtime),
            stop,
        })
    }

    pub fn start(&mut self, name: &str) -> ApiResponse {
        let response = timeout_on(
            self.runtime
                .as_mut()
                .unwrap()
                .request(api::model::Request::Start(name.to_string())),
        )
        .and_then(|result| result.wrap_err("Failed to start container"));
        ApiResponse(response)
    }

    pub async fn pid(&mut self, name: &str) -> Result<u32> {
        let response = timeout(
            TIMEOUT,
            self.runtime
                .as_mut()
                .unwrap()
                .request(api::model::Request::Containers),
        )
        .await
        .wrap_err("Getting containers status timed out")
        .and_then(|result| result.wrap_err("Failed to get container status"))?;

        match response {
            api::model::Response::Containers(containers) => containers
                .into_iter()
                .filter(|c| c.manifest.name == name)
                .filter_map(|c| c.process.map(|p| p.pid))
                .next()
                .ok_or_else(|| eyre!("Failed to find PID")),
            api::model::Response::Err(e) => Err(eyre!("Failed to request containers: {:?}", e)),
            _ => unreachable!(),
        }
    }

    pub fn stop(&mut self, name: &str) -> ApiResponse {
        let response = timeout_on(
            self.runtime
                .as_mut()
                .unwrap()
                .request(api::model::Request::Stop(name.to_string())),
        )
        .and_then(|result| result.wrap_err("Failed to stop container"));
        ApiResponse(response)
    }

    pub fn install(&mut self, npk: &Path) -> ApiResponse {
        let response = timeout_on(self.runtime.as_mut().unwrap().install("default", npk))
            .and_then(|result| result.wrap_err("Failed to install container"));
        ApiResponse(response)
    }

    pub fn uninstall(&mut self, name: &str, version: &str) -> ApiResponse {
        let uninstall = api::model::Request::Uninstall(
            name.to_string(),
            npk::manifest::Version::parse(version).expect("Failed to parse version"),
        );

        let response = timeout_on(self.runtime.as_mut().unwrap().request(uninstall))
            .and_then(|result| result.wrap_err("Failed to uninstall container"));
        ApiResponse(response)
    }

    pub fn shutdown(mut self) -> Result<()> {
        let shutdown = api::model::Request::Shutdown;
        timeout_on(self.runtime.as_mut().unwrap().request(shutdown))
            .and_then(|result| result.wrap_err("Failed to shutdown runtime"))?;

        timeout_on(self.runtime.take().unwrap().wait())?
            .wrap_err("Failed to wait for runtime termination")
    }
}

/// Returns a path to a directory overlay-ed on top of the input directory
/// Notice that this function is meant to be called inside a mount namespace
/// Every change done to this directory is discarded at the end of the test
fn overlay_directory(dir: &Path) -> Result<PathBuf> {
    let repository = TempDir::new()?.into_path();
    let workdir = repository.join("workdir");
    let target = repository.join("target");
    let upper = repository.join("upper");

    std::fs::create_dir(&workdir)?;
    std::fs::create_dir(&target)?;
    std::fs::create_dir(&upper)?;

    use std::os::unix::ffi::OsStrExt;
    let mut options = Vec::new();
    options.extend(b"lowerdir=");
    options.extend_from_slice(dir.as_os_str().as_bytes());
    options.extend(b",upperdir=");
    options.extend_from_slice(upper.as_os_str().as_bytes());
    options.extend(b",workdir=");
    options.extend_from_slice(workdir.as_os_str().as_bytes());

    nix::mount::mount(
        Some("overlay"),
        &target,
        Some("overlay"),
        MsFlags::empty(),
        Some(&*options),
    )
    .map_err(|e| eyre!("Failed to mount overlay repository ({})", e))?;

    Ok(target)
}
