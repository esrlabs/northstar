// Copyright (c) 2020 ESRLabs
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

use anyhow::Result;
use futures::StreamExt;
use itertools::Itertools;
use northstar::{api::{
    self,
    client::Client,
    model::{Container, Notification, Repository},
}, runtime::RepositoryId};
use prettytable::{format, Attr, Cell, Row, Table};
use std::{
    collections::HashMap,
    fmt::Debug,
    io::{self, Write},
};
use structopt::StructOpt;
use tokio::{select, time};

mod terminal;

#[derive(Debug, StructOpt)]
#[structopt(name = "nstar", about = "Northstar CLI")]
struct Opt {
    /// File that contains the northstar configuration
    #[structopt(short, long, default_value = "localhost:4200")]
    host: String,

    /// Run command and exit
    cmd: Vec<String>,
}

fn format_notification<W: io::Write>(mut w: W, notification: &Notification) {
    let msg = format!("--> {:?}", notification);
    writeln!(w, "{}", msg).ok();
}

fn format_containers<W: io::Write>(mut w: W, containers: &[Container]) -> Result<()> {
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(Row::new(vec![
        Cell::new("Name").with_style(Attr::Bold),
        Cell::new("Version").with_style(Attr::Bold),
        Cell::new("Repository").with_style(Attr::Bold),
        Cell::new("Type").with_style(Attr::Bold),
        Cell::new("PID").with_style(Attr::Bold),
        Cell::new("Uptime").with_style(Attr::Bold),
    ]));
    for container in containers
        .iter()
        .sorted_by_key(|c| &c.manifest.name) // Sort by name
        .sorted_by_key(|c| c.manifest.init.is_none())
    {
        table.add_row(Row::new(vec![
            Cell::new(&container.manifest.name).with_style(Attr::Bold),
            Cell::new(&container.manifest.version.to_string()),
            Cell::new(&container.repository),
            Cell::new(
                container
                    .manifest
                    .init
                    .as_ref()
                    .map(|_| "App")
                    .unwrap_or("Resource"),
            ),
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

    print_table(&mut w, &table)?;
    w.flush()?;
    Ok(())
}

fn format_repositories<W: io::Write>(
    mut w: W,
    repositories: &HashMap<RepositoryId, Repository>,
) -> Result<()> {
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(Row::new(vec![
        Cell::new("Name").with_style(Attr::Bold),
        Cell::new("Path").with_style(Attr::Bold),
    ]));
    for (id, repo) in repositories.iter().sorted_by_key(|(i, _)| (*i).clone())
    // Sort by name
    {
        table.add_row(Row::new(vec![
            Cell::new(&id).with_style(Attr::Bold),
            Cell::new(&repo.dir.display().to_string()),
        ]));
    }

    print_table(&mut w, &table)?;
    w.flush()?;
    Ok(())
}

fn print_table<W: std::io::Write>(mut w: W, table: &Table) -> Result<()> {
    w.write_all(table.to_string().as_bytes())?;
    w.write_all(b"\n")?;
    Ok(())
}

async fn process(
    client: &mut Client,
    terminal: &mut terminal::Terminal,
    input: &str,
) -> Result<()> {
    let mut split = input.split_whitespace();
    if let Some(cmd) = split.next() {
        match cmd {
            "containers" | "ls" => {
                let containers = client.containers().await?;
                format_containers(terminal, &containers)?;
            }
            "repositories" => {
                let repositories = client.repositories().await?;
                format_repositories(terminal, &repositories)?;
            }
            "start" => {
                let mut containers = client.containers().await?;
                let containers = containers
                    .drain(..)
                    .filter(|c| c.manifest.init.is_some()) // Filter resource containers
                    .filter(|c| c.process.is_none()) // Filter started containers
                    .map(|c| c.manifest.name)
                    .collect::<Vec<_>>();
                if let Some(n) = split.next() {
                    // Exact match
                    if containers.iter().any(|c| c == n) {
                        client.start(n).await?;
                    } else {
                        let re = regex::Regex::new(n)?;
                        for name in containers.iter().filter(|c| re.is_match(&c)) {
                            client.start(&name).await?;
                        }
                    }
                } else {
                    // No argument - stop all running containers
                    for name in &containers {
                        client.start(&name).await?;
                    }
                }
            }
            "stop" => {
                let mut containers = client.containers().await?;
                let containers = containers
                    .drain(..)
                    .filter(|c| c.manifest.init.is_some()) // Filter resource containers
                    .filter(|c| c.process.is_some()) // Filter stopped containers
                    .map(|c| c.manifest.name)
                    .collect::<Vec<_>>();
                if let Some(n) = split.next() {
                    // Exact match
                    if containers.iter().any(|c| c == n) {
                        client.stop(n).await?;
                    } else {
                        let re = regex::Regex::new(n)?;
                        for name in containers.iter().filter(|c| re.is_match(&c)) {
                            client.stop(&name).await?;
                        }
                    }
                } else {
                    // No argument - stop all running containers
                    for name in &containers {
                        client.stop(&name).await?;
                    }
                }
            }
            _ => (),
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();
    let interactive = opt.cmd.is_empty();
    let mut terminal = terminal::Terminal::new()?;

    'outer: loop {
        writeln!(terminal, "Connecting to {}", opt.host)?;

        let mut client = match time::timeout(
            time::Duration::from_secs(2),
            api::client::Client::new(&opt.host),
        )
        .await
        {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                writeln!(terminal, "Failed to connect: {:?}", e)?;
                time::sleep(time::Duration::from_secs(1)).await;
                continue 'outer;
            }
            Err(_) => {
                writeln!(terminal, "Failed to connect: timeout")?;
                time::sleep(time::Duration::from_secs(1)).await;
                continue 'outer;
            }
        };

        writeln!(terminal, "Connected to {}", opt.host)?;

        loop {
            select! {
                notification = client.next() => {
                    if let Some(Ok(n)) = notification {
                        format_notification(&mut terminal, &n);
                    } else {
                        break;
                    }
                }
                input = terminal.next() => {
                    if let Some(input) = input {
                        if let Err(e) = process(&mut client, &mut terminal, &input).await {
                            writeln!(&mut terminal, "Error: {:?}", e)?;
                            break;
                        }
                    } else {
                        break 'outer;
                    };
                }
            }
        }

        if interactive {
            writeln!(terminal, "Disconnected")?;
            time::sleep(time::Duration::from_secs(1)).await;
        } else {
            break;
        }
    }
    Ok(())
}
