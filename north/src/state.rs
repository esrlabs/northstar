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

use crate::{keys, npk, npk::Container, process::Process, EventTx, Name, TerminationReason};
use anyhow::{anyhow, Result};
use ed25519_dalek::PublicKey;
use log::{info, warn};
use north_common::manifest::{Manifest, OnExit, Version};
use std::{collections::HashMap, fmt, iter, time};

pub struct State {
    tx: EventTx,
    pub signing_keys: HashMap<String, PublicKey>,
    pub applications: HashMap<Name, Application>,
}

pub struct Application {
    container: Container,
    process: Option<ProcessContext>,
}

pub struct ProcessContext<T: Process> {
    process: T,
    incarnation: u32,
    start_timestamp: time::Instant,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    cgroups: Option<crate::linux::cgroups::CGroups>,
}

impl ProcessContext<T> {
    pub fn process(&self) -> &Process {
        &self.process
    }

    pub fn uptime(&self) -> time::Duration {
        self.start_timestamp.elapsed()
    }
}

impl Application {
    pub fn new(container: Container) -> Application {
        Application {
            container,
            process: None,
        }
    }

    pub fn name(&self) -> &Name {
        &self.manifest().name
    }

    pub fn version(&self) -> &Version {
        &self.manifest().version
    }

    pub fn manifest(&self) -> &Manifest {
        &self.container.manifest
    }

    pub fn container(&self) -> &Container {
        &self.container
    }

    pub fn process_context(&self) -> Option<&ProcessContext> {
        self.process.as_ref()
    }
}

impl fmt::Display for Application {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.manifest().name, self.version())
    }
}

impl State {
    /// Create a new empty State instance
    pub async fn new(tx: EventTx) -> Result<State> {
        // Load keys for manifest verification
        let signing_keys = keys::load().await?;

        Ok(State {
            tx,
            signing_keys,
            applications: HashMap::new(),
        })
    }

    /// Return an owned copy of the main loop tx handle
    pub fn tx(&self) -> EventTx {
        self.tx.clone()
    }

    /// Return an iterator over all known applications
    pub fn applications(&self) -> impl iter::Iterator<Item = &Application> {
        self.applications.values()
    }

    /// Try to find a application with name `name`
    pub fn application(&mut self, name: &str) -> Option<&Application> {
        self.applications.get(name)
    }

    /// Add a container instance the list of known containers
    pub fn add(&mut self, container: Container) -> Result<()> {
        // TODO: check for dups
        let name = container.manifest.name.clone();
        let app = Application::new(container);
        self.applications.insert(name, app);
        Ok(())
    }

    /// Remove and umount a specific container
    pub async fn uninstall(&mut self, name: &str) -> Result<()> {
        if let Some(app) = self.applications.get_mut(name) {
            if app.process_context().is_none() {
                info!("Removing {}", app);
                npk::uninstall(app.container()).await?;
                self.applications.remove(name);
                Ok(())
            } else {
                warn!("Cannot uninstall running container {}", app);
                Err(anyhow!("Cannot uninstall running container {}", app))
            }
        } else {
            warn!("Cannot uninstall unknown container {}", name);
            Err(anyhow!("Cannot uninstall unknown container {}", name))
        }
    }

    /// Start a container with name `name`
    pub async fn start(&mut self, name: &str, incarnation: u32) -> Result<()> {
        let available_resource_ids: Vec<String> = self
            .applications
            .values()
            .map(|a| &a.container)
            .filter(|c| c.is_resource_container())
            .map(|c| c.manifest.name.clone())
            .collect();
        if let Some(app) = self.applications.get_mut(name) {
            if app.container.is_resource_container() {
                warn!("Cannot start resource containers ({})", app);
                return Err(anyhow!("Attempted to start resource container {}", name));
            }
            if let Some(required_resources) = &app.container.manifest.resources {
                for r in required_resources {
                    if !available_resource_ids.contains(&r.name) {
                        warn!(
                            "Container {} missing required resource \"{}\")",
                            name, &r.name
                        );
                        return Err(anyhow!(
                            "Failed to start {} because of missing resource \"{}\"",
                            name,
                            r.name
                        ));
                    }
                }
            }
            info!("Starting {}", app);
            let process = Process::spawn(&app.container, self.tx.clone()).await?;
            #[cfg(any(target_os = "android", target_os = "linux"))]
            let cgroups = if let Some(ref c) = app.manifest().cgroups {
                log::debug!("Creating cgroup configuration for {}", app);
                let cgroups =
                    crate::linux::cgroups::CGroups::new(app.name(), c, self.tx.clone()).await?;

                log::debug!("Assigning {} to cgroup {}", process.pid(), app);
                cgroups.assign(process.pid()).await?;
                Some(cgroups)
            } else {
                None
            };
            app.process = Some(ProcessContext {
                process,
                incarnation,
                start_timestamp: time::Instant::now(),
                #[cfg(any(target_os = "android", target_os = "linux"))]
                cgroups,
            });
            info!("Started {}", app);
            Ok(())
        } else {
            Err(anyhow!("Invalid application {}", name))
        }
    }

    /// Stop a application. Timeout specifies the time until the process is
    /// SIGKILLed if it doesn't exit when receiving a SIGTERM
    pub async fn stop(
        &mut self,
        name: &str,
        timeout: time::Duration,
        reason: TerminationReason,
    ) -> Result<()> {
        if let Some(app) = self.applications.get_mut(name) {
            if let Some(mut context) = app.process.take() {
                info!("Stopping {}", app);
                let status = context
                    .process
                    .terminate(timeout, Some(reason))
                    .await?
                    .await;

                #[cfg(any(target_os = "android", target_os = "linux"))]
                {
                    if let Some(cgroups) = context.cgroups {
                        log::debug!("Destroying cgroup configuration of {}", app);
                        cgroups.destroy().await?;
                    }
                }

                info!("Stopped {} {:?}", app, status);
            } else {
                warn!("Application {} is not running", app);
            }
            Ok(())
        } else {
            Err(anyhow!("Invalid application {}", name))
        }
    }

    /// Handle the exit of a container. The restarting of containers is a subject
    /// to be removed and handled externally
    #[allow(unused_mut)]
    pub async fn on_exit(&mut self, name: &str, return_code: i32) -> Result<()> {
        if let Some(app) = self.applications.get_mut(name) {
            if let Some(mut context) = app.process.take() {
                info!(
                    "Process {} exited after {:?} with code {} and termination reason {:?}",
                    app,
                    context.start_timestamp.elapsed(),
                    return_code,
                    context.process.termination_reason()
                );

                #[cfg(any(target_os = "android", target_os = "linux"))]
                {
                    if let Some(cgroups) = context.cgroups.take() {
                        log::debug!("Destroying cgroup configuration of {}", app);
                        cgroups.destroy().await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle out of memory conditions for container `name`
    pub async fn on_oom(&mut self, name: &str) -> Result<()> {
        if let Some(app) = self.applications.get_mut(name) {
            warn!("Process {} is out of memory. Stopping {}", app, app);
            self.stop(
                name,
                time::Duration::from_secs(1),
                TerminationReason::OutOfMemory,
            )
            .await?;
        }
        Ok(())
    }
}
