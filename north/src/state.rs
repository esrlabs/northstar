// Copyright (c) 2020 E.S.R.Labs. All rights reserved.
//
// NOTICE:  All information contained herein is, and remains
// the property of E.S.R.Labs and its suppliers, if any.
// The intellectual and technical concepts contained herein are
// proprietary to E.S.R.Labs and its suppliers and may be covered
// by German and Foreign Patents, patents in process, and are protected
// by trade secret or copyright law.
// Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained
// from E.S.R.Labs.

use crate::{
    cgroups::CGroups, container, container::Container, process::Process, EventTx, Name,
    TerminationReason,
};
use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use north_common::manifest::{Manifest, OnExit, Version};
use std::{collections::HashMap, fmt, iter, time};

#[derive(Debug)]
pub struct State {
    tx: EventTx,
    pub applications: HashMap<Name, Application>,
}

#[derive(Debug)]
pub struct Application {
    container: Container,
    process: Option<ProcessContext>,
}

#[derive(Debug)]
pub struct ProcessContext {
    process: Process,
    cgroups: Option<CGroups>,
    incarnation: u32,
    start_timestamp: time::Instant,
}

impl ProcessContext {
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
    pub fn new(tx: EventTx) -> State {
        State {
            tx,
            applications: HashMap::new(),
        }
    }

    pub fn tx(&self) -> EventTx {
        self.tx.clone()
    }

    pub fn applications(&self) -> impl iter::Iterator<Item = &Application> {
        self.applications.values()
    }

    pub fn application(&mut self, name: &str) -> Option<&Application> {
        self.applications.get(name)
    }

    pub fn add(&mut self, container: Container) -> Result<()> {
        // TODO: check for dups
        let name = container.manifest.name.clone();
        let app = Application::new(container);
        self.applications.insert(name, app);
        Ok(())
    }

    pub async fn uninstall(&mut self, name: &str) -> Result<()> {
        if let Some(app) = self.applications.get_mut(name) {
            if app.process_context().is_none() {
                info!("Uninstalling {}", app);
                container::uninstall(app.container()).await?;
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

    pub async fn start(&mut self, name: &str, incarnation: u32) -> Result<()> {
        if let Some(app) = self.applications.get_mut(name) {
            info!("Starting {}", app);
            let process = Process::spawn(&app.container, self.tx.clone()).await?;
            let cgroups = if let Some(ref c) = app.manifest().cgroups {
                debug!("Creating cgroup configuration for {}", app);
                let cgroups = CGroups::new(app.name(), c, self.tx.clone()).await?;

                debug!("Assigning {} to cgroup {}", process.pid(), app);
                cgroups.assign(process.pid()).await?;
                Some(cgroups)
            } else {
                None
            };
            app.process = Some(ProcessContext {
                cgroups,
                process,
                incarnation,
                start_timestamp: time::Instant::now(),
            });
            info!("Started {}", app);
            Ok(())
        } else {
            Err(anyhow!("Invalid application {}", name))
        }
    }

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

                if let Some(cgroups) = context.cgroups {
                    debug!("Destroying cgroup configuration of {}", app);
                    cgroups.destroy().await?;
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
                if let Some(cgroups) = context.cgroups.take() {
                    debug!("Destroying cgroup configuration of {}", app);
                    cgroups.destroy().await?;
                }

                if let Some(OnExit::Restart(n)) = app.manifest().on_exit {
                    if context.incarnation < n {
                        info!(
                            "Restarting {} in incarnation {}",
                            app,
                            context.incarnation + 1
                        );
                        self.start(name, context.incarnation + 1).await?;
                    }
                }
            }
        }
        Ok(())
    }

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
