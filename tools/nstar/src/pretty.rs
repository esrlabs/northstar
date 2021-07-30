// Copyright (c) 2021 ESRLabs
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

use itertools::Itertools;
use model::ExitStatus;
use northstar::api::model::{
    self, ContainerData, MountResult, Notification, RepositoryId, Response,
};
use prettytable::{format, Attr, Cell, Row, Table};
use std::collections::HashSet;
use tokio::time;

pub(crate) fn notification(notification: &Notification) {
    match notification {
        Notification::OutOfMemory(c) => println!("container {} is out of memory", c),
        Notification::Exit(container, status) => println!(
            "container {} exited with status {}",
            container,
            match status {
                ExitStatus::Exit(code) => format!("exit code {}", code),
                ExitStatus::Signaled(signal) => format!("signaled {}", signal),
            }
        ),
        Notification::Install(container) => println!("installed {}", container),
        Notification::Uninstall(container) => println!("uninstalled {}", container),
        Notification::Started(container) => println!("started {}", container),
        Notification::Stopped(container, status) => {
            println!(
                "stopped {} with status {}",
                container,
                match status {
                    ExitStatus::Exit(code) => format!("exit code {}", code),
                    ExitStatus::Signaled(signal) => format!("signaled {}", signal),
                }
            )
        }
        Notification::Shutdown => println!("shutting down"),
    }
}

pub(crate) fn containers(containers: &[ContainerData]) {
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(Row::new(vec![
        Cell::new("Name").with_style(Attr::Bold),
        Cell::new("Version").with_style(Attr::Bold),
        Cell::new("Repository").with_style(Attr::Bold),
        Cell::new("Type").with_style(Attr::Bold),
        Cell::new("Mounted").with_style(Attr::Bold),
        Cell::new("PID").with_style(Attr::Bold),
        Cell::new("Uptime").with_style(Attr::Bold),
    ]));
    for container in containers
        .iter()
        .sorted_by_key(|c| c.manifest.name.to_string())
        .sorted_by_key(|c| c.manifest.init.is_none())
    {
        table.add_row(Row::new(vec![
            Cell::new(container.container.name()).with_style(Attr::Bold),
            Cell::new(&container.container.version().to_string()),
            Cell::new(&container.repository),
            Cell::new(
                container
                    .manifest
                    .init
                    .as_ref()
                    .map(|_| "App")
                    .unwrap_or("Resource"),
            ),
            Cell::new(if container.mounted { "yes" } else { "no" }),
            Cell::new(
                &container
                    .process
                    .as_ref()
                    .map(|p| p.pid.to_string())
                    .unwrap_or_default(),
            )
            .with_style(Attr::ForegroundColor(prettytable::color::GREEN)),
            Cell::new(
                &container
                    .process
                    .as_ref()
                    .map(|p| format!("{:?}", time::Duration::from_nanos(p.uptime)))
                    .unwrap_or_default(),
            ),
        ]));
    }

    table.printstd();
}

pub fn repositories(repositories: &HashSet<RepositoryId>) {
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(Row::new(vec![Cell::new("Name").with_style(Attr::Bold)]));
    for repository in repositories.iter().sorted_by_key(|i| (*i).clone()) {
        table.add_row(Row::new(vec![Cell::new(repository).with_style(Attr::Bold)]));
    }

    table.printstd();
}

pub fn mounts(mounts: &[MountResult]) {
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(Row::new(vec![
        Cell::new("Name").with_style(Attr::Bold),
        Cell::new("Path").with_style(Attr::Bold),
    ]));
    for result in mounts {
        let row = match result {
            MountResult::Ok(c) => {
                vec![
                    Cell::new(&c.to_string()).with_style(Attr::Bold),
                    Cell::new("ok"),
                ]
            }
            MountResult::Err((c, e)) => {
                vec![
                    Cell::new(&c.to_string()).with_style(Attr::Bold),
                    Cell::new(&format_err(e)),
                ]
            }
        };
        table.add_row(Row::new(row));
    }

    table.printstd();
}

pub fn response(response: &Response) -> i32 {
    match response {
        Response::Containers(cs) => {
            containers(cs);
            0
        }
        Response::Repositories(rs) => {
            repositories(rs);
            0
        }
        Response::Mount(results) => {
            mounts(results);
            0
        }
        Response::Ok(()) => {
            println!("ok");
            0
        }
        Response::Err(e) => {
            eprintln!("{}", format_err(e));
            1
        }
    }
}

fn format_err(err: &model::Error) -> String {
    match err {
        model::Error::Configuration(cause) => format!("invalid configuration: {}", cause),
        model::Error::DuplicateContainer(container) => {
            format!("duplicate container name and version {}", container)
        }
        model::Error::InvalidContainer(c) => format!("invalid container {}", c),
        model::Error::InvalidArguments(c) => format!("invalid arguments {}", c),
        model::Error::MountBusy(c) => format!("failed to mount {}: busy", c),
        model::Error::UmountBusy(c) => format!("failed to umount {}: busy", c),
        model::Error::StartContainerStarted(c) => {
            format!("failed to start container {}: already started", c)
        }
        model::Error::StartContainerResource(c) => {
            format!("failed to start container {}: resource", c)
        }
        model::Error::StartContainerMissingResource(c, r) => {
            format!("failed to start container {}: missing resource {}", c, r)
        }
        model::Error::StartContainerFailed(c, r) => {
            format!("failed to start container {}: {}", c, r)
        }
        model::Error::StopContainerNotStarted(c) => {
            format!("failed to stop container {}: not started", c)
        }
        model::Error::InvalidRepository(r) => format!("invalid repository {}", r),
        model::Error::InstallDuplicate(c) => {
            format!("failed to install {}: installed", c)
        }
        model::Error::CriticalContainer(c, s) => {
            format!(
                "critical container {} exited with: {}",
                c,
                match s {
                    ExitStatus::Exit(c) => format!("exit code {}", c),
                    ExitStatus::Signaled(s) => format!("signaled {}", s),
                }
            )
        }
        model::Error::Npk(npk, e) => format!("npk error: {}: {}", npk, e),
        model::Error::Process(e) => format!("process error: {}", e),
        model::Error::Console(e) => format!("console error: {}", e),
        model::Error::Cgroups(e) => format!("cgroups error: {}", e),
        model::Error::Mount(e) => format!("mount error: {}", e),
        model::Error::Key(e) => format!("key error: {}", e),
        model::Error::Io(e) => format!("io error: {}", e),
        model::Error::Os(e) => format!("os error: {}", e),
        model::Error::Name(e) => format!("name error: {}", e),
    }
}
