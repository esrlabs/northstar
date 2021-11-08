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
        Notification::CGroup {
            container,
            notification,
        } => {
            println!("container {} memory event {:?}", container, notification)
        }
        Notification::Exit { container, status } => println!(
            "container {} exited with status {}",
            container,
            match status {
                ExitStatus::Exit { code } => format!("exit code {}", code),
                ExitStatus::Signalled { signal } => format!("signaled {}", signal),
            }
        ),
        Notification::Install { container } => println!("installed {}", container),
        Notification::Uninstall { container } => println!("uninstalled {}", container),
        Notification::Started { container } => println!("started {}", container),
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
            MountResult::Ok { container } => {
                vec![
                    Cell::new(&container.to_string()).with_style(Attr::Bold),
                    Cell::new("ok"),
                ]
            }
            MountResult::Error { container, error } => {
                vec![
                    Cell::new(&container.to_string()).with_style(Attr::Bold),
                    Cell::new(&format_err(error)),
                ]
            }
        };
        table.add_row(Row::new(row));
    }

    table.printstd();
}

pub fn response(response: &Response) -> i32 {
    match response {
        Response::Containers { containers: c } => {
            containers(c);
            0
        }
        Response::Repositories { repositories: r } => {
            repositories(r);
            0
        }
        Response::Mount { result } => {
            mounts(result);
            0
        }
        Response::Ok => {
            println!("ok");
            0
        }
        Response::ContainerStats { container, stats } => {
            println!("{}:", container);
            println!("{}", serde_json::to_string_pretty(&stats).unwrap());
            0
        }
        Response::Error { error } => {
            eprintln!("{}", format_err(error));
            1
        }
    }
}

fn format_err(err: &model::Error) -> String {
    match err {
        model::Error::Configuration { context } => format!("invalid configuration: {}", context),
        model::Error::DuplicateContainer { container } => {
            format!("duplicate container name and version {}", container)
        }
        model::Error::InvalidContainer { container } => format!("invalid container {}", container),
        model::Error::InvalidArguments { cause } => format!("invalid arguments {}", cause),
        model::Error::MountBusy { container } => format!("container busy: {}", container),
        model::Error::UmountBusy { container } => format!("container busy: {}", container),
        model::Error::StartContainerStarted { container } => {
            format!("failed to start container {}: already started", container)
        }
        model::Error::StartContainerResource { container } => {
            format!("failed to start container {}: resource", container)
        }
        model::Error::StartContainerMissingResource {
            container,
            resource,
        } => {
            format!(
                "failed to start container {}: missing resource {}",
                container, resource
            )
        }
        model::Error::StartContainerFailed { container, error } => {
            format!("failed to start container {}: {}", container, error)
        }
        model::Error::StopContainerNotStarted { container } => {
            format!("failed to stop container {}: not started", container)
        }
        model::Error::InvalidRepository { repository } => {
            format!("invalid repository {}", repository)
        }
        model::Error::InstallDuplicate { container } => {
            format!("failed to install {}: installed", container)
        }
        model::Error::CriticalContainer { container, status } => {
            format!(
                "critical container {} exited with: {}",
                container,
                match status {
                    ExitStatus::Exit { code } => format!("exit code {}", code),
                    ExitStatus::Signalled { signal } => format!("signaled {}", signal),
                }
            )
        }
        model::Error::Unexpected { module, error } => format!("{}: {}", module, error),
    }
}
