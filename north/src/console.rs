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

use crate::{Event, EventTx, Name, State, TerminationReason, SETTINGS};
use anyhow::{anyhow, Context, Result};
use async_std::{io, net::TcpListener, path::PathBuf, prelude::*, sync, task};
use itertools::Itertools;
use log::{debug, warn, *};
use prettytable::{format, Table};
use std::{iter, time};

/// Helptext displayed on the `help` command. The `dcon` tool parses this text
/// and creates suggestions and completions. Ensure to a correct helptext when
/// adding/removing/changing commands.
const HELP: &str = "\
    help: Display help text\n\
    list: List all loaded images\n\
    ps: List running instances\n\
    shutdown: Stop the north runtime\n\
    settings: Dump north configuration\n\
    start: PATTERN Start containers matching PATTERN e.g 'start hello*'. Omit PATTERN to start all containers\n\
    stop: PATTERN Stop all containers matching PATTERN. Omit PATTERN to stop all running containers\n\
    uninstall: PATTERN: Unmount and remove all containers matching PATTERN\n\
    update: Run update with provided ressources\n\
    versions: Version list of installed applications";

pub async fn init(tx: &EventTx) -> Result<()> {
    let rx = serve().await?;
    let tx = tx.clone();
    // Spawn a task that handles lines received on the debug port.
    task::spawn(async move {
        while let Ok((line, tx_reply)) = rx.recv().await {
            tx.send(Event::Console(line, tx_reply)).await;
        }
    });

    Ok(())
}

pub async fn process(state: &mut State, command: &str, reply: sync::Sender<String>) -> Result<()> {
    info!("Running \'{}\'", command);
    let mut commands = command.split_whitespace();

    if let Some(cmd) = commands.next() {
        let args = commands.collect::<Vec<&str>>();
        let start_timestamp = time::Instant::now();
        match match cmd {
            "help" => help(),
            "list" => list(state).await,
            "ps" => ps(state).await,
            "settings" => settings(),
            "shutdown" => shutdown(state).await,
            "start" => start(state, &args).await,
            "stop" => stop(state, &args).await,
            "uninstall" => uninstall(state, &args).await,
            "update" => update(state, &args).await,
            "versions" => versions(state),
            _ => Err(anyhow!("Unknown command: {}", command)),
        } {
            Ok(mut r) => {
                r.push_str(&format!("Duration: {:?}\n", start_timestamp.elapsed()));
                reply.send(r).await
            }
            Err(e) => {
                let msg = format!("Failed to run: {} {:?}: {}\n", cmd, args, e);
                reply.send(msg).await
            }
        }
    } else {
        reply.send("Invalid command".into()).await
    }
    Ok(())
}

/// Return the help text
fn help() -> Result<String> {
    Ok(HELP.into())
}

/// List all known containers instances and their state.
async fn list(state: &State) -> Result<String> {
    to_table(
        vec![vec![
            "Name".to_string(),
            "Version".to_string(),
            "Running".to_string(),
            "Type".to_string(),
        ]]
        .iter()
        .cloned()
        .chain(
            state
                .applications()
                .sorted_by_key(|app| app.name())
                .map(|app| {
                    vec![
                        app.name().to_string(),
                        app.version().to_string(),
                        app.process_context()
                            .map(|c| format!("Yes (pid: {})", c.process().pid()))
                            .unwrap_or_else(|| "No".to_string()),
                        if app.container().is_resource_container() {
                            "resource"
                        } else {
                            "app"
                        }
                        .to_owned(),
                    ]
                }),
        ),
    )
}

/// List all running applications.
#[cfg(all(not(target_os = "android"), not(target_os = "linux")))]
async fn ps(state: &State) -> Result<String> {
    to_table(
        vec![vec![
            "Name".to_string(),
            "Version".to_string(),
            "Uptime".to_string(),
        ]]
        .iter()
        .cloned()
        .chain(
            state
                .applications()
                .filter_map(|app| app.process_context().map(|p| (app, p)))
                .sorted_by_key(|(app, _)| app.name())
                .map(|(app, context)| {
                    vec![
                        app.name().to_string(),
                        app.version().to_string(),
                        format!("{:?}", context.uptime()),
                    ]
                }),
        ),
    )
}

/// List all running applications.
#[cfg(any(target_os = "android", target_os = "linux"))]
async fn ps(state: &State) -> Result<String> {
    use pretty_bytes::converter::convert;
    const PAGE_SIZE: usize = 4096;

    let mut result = vec![[
        "Name", "Version", "PID", "Size", "Resident", "Shared", "Text", "Data", "Uptime",
    ]
    .iter()
    .map(ToString::to_string)
    .collect()];

    for app in state.applications().sorted_by_key(|app| app.name()) {
        if let Some(ref context) = app.process_context() {
            let pid = context.process().pid();
            let statm = procinfo::pid::statm(pid as i32)?;
            result.push(vec![
                app.name().to_string(),
                app.version().to_string(),
                pid.to_string(),
                convert((statm.size * PAGE_SIZE) as f64),
                convert((statm.resident * PAGE_SIZE) as f64),
                convert((statm.share * PAGE_SIZE) as f64),
                convert((statm.text * PAGE_SIZE) as f64),
                convert((statm.data * PAGE_SIZE) as f64),
                format!("{:?}", context.uptime()),
            ]);
        }
    }

    to_table(result)
}

/// Start applications. If `args` is empty *all* known applications that
/// are not in a running state are started. If a argument is supplied it
/// is used to construct a Regex and all container (names) matching that
/// Regex are attempted to be started.
async fn start(state: &mut State, args: &[&str]) -> Result<String> {
    let re = arg_regex(args)?;

    let mut result = vec![vec![
        "Name".to_string(),
        "Result".to_string(),
        "Duration".to_string(),
    ]];
    let apps = state
        .applications()
        // Filter for not already running containers
        .filter(|app| app.process_context().is_none())
        // Filter ressource container that are not startable
        .filter(|app| !app.container().is_resource_container())
        // Filter matching container
        .filter(|app| re.is_match(app.name()))
        // Sort container by name
        .sorted_by_key(|app| app.name().clone())
        .map(|app| app.name().clone())
        .collect::<Vec<Name>>();
    for app in &apps {
        let start = time::Instant::now();
        match state.start(&app, 0).await {
            Ok(_) => result.push(vec![
                app.to_string(),
                "Ok".to_string(),
                format!("{:?}", start.elapsed()),
            ]),
            Err(e) => result.push(vec![
                app.to_string(),
                format!("Failed: {:?}", e),
                format!("{:?}", start.elapsed()),
            ]),
        }
    }

    to_table(result)
}

/// Dump settings
fn settings() -> Result<String> {
    Ok(format!("{}", *SETTINGS))
}

/// Stop one, some or all containers. See start for the argument handling.
async fn stop(state: &mut State, args: &[&str]) -> Result<String> {
    let re = arg_regex(args)?;

    let mut result = vec![vec![
        "Name".to_string(),
        "Result".to_string(),
        "Duration".to_string(),
    ]];
    let apps = state
        .applications()
        .filter(|app| app.process_context().is_some())
        .filter(|app| re.is_match(app.name()))
        .map(|app| app.name().clone())
        .collect::<Vec<Name>>();
    for app in &apps {
        let timeout = time::Duration::from_secs(10);
        let reason = TerminationReason::Stopped;
        let start = time::Instant::now();
        match state.stop(&app, timeout, reason).await {
            Ok(()) => result.push(vec![
                app.to_string(),
                "Ok".to_string(),
                format!("{:?}", start.elapsed()),
            ]),

            Err(e) => result.push(vec![
                app.to_string(),
                e.to_string(),
                format!("{:?}", start.elapsed()),
            ]),
        }
    }

    to_table(result)
}

/// Umount and remove a containers. See `start` for the argument handling.
/// The data directory is not removed. This needs discussion.
async fn uninstall(state: &mut State, args: &[&str]) -> Result<String> {
    let re = arg_regex(args)?;

    let mut result = vec![vec!["Name".to_string(), "Result".to_string()]];

    let to_uninstall = state
        .applications
        .values()
        .filter(|app| app.process_context().is_none())
        .filter(|app| re.is_match(app.name()))
        .map(|app| app.name())
        .cloned()
        .collect::<Vec<Name>>();

    for app in &to_uninstall {
        match state.uninstall(&app).await {
            Ok(()) => result.push(vec![app.to_string(), "Ok".to_string()]),
            Err(e) => result.push(vec![app.to_string(), e.to_string()]),
        }
    }

    to_table(result)
}

/// Trigger the update module.
async fn update(state: &mut State, args: &[&str]) -> Result<String> {
    if args.len() != 1 {
        return Err(anyhow!("Invalid arguments for update command"));
    }

    let dir = PathBuf::from(args[0]);

    if !dir.exists().await {
        let err = anyhow!("Update directory {} does not exists", dir.display());
        Err(err)
    } else {
        let updates = crate::update::update(state, &dir).await?;

        let mut result = vec![vec![
            "Name".to_string(),
            "From".to_string(),
            "To".to_string(),
        ]];
        for update in &updates {
            result.push(vec![
                update.0.to_string(),
                (update.1).0.to_string(),
                (update.1).1.to_string(),
            ])
        }
        to_table(result)
    }
}

/// Send a shutdown command to the main loop.
async fn shutdown(state: &mut State) -> Result<String> {
    let stop = stop(state, &[]).await?;
    state.tx().send(Event::Shutdown).await;

    Ok(stop)
}

/// Open a TCP socket and read lines terminated with `\n`.
async fn serve() -> Result<sync::Receiver<(String, sync::Sender<String>)>> {
    let address = &SETTINGS.console_address;

    debug!("Starting console on {}", address);

    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("Failed to open listener on {}", address))?;
    let (tx, rx) = sync::channel(1000);

    task::spawn(async move {
        let mut incoming = listener.incoming();

        // Spawn a task for each incoming connection.
        while let Some(stream) = incoming.next().await {
            let (tx_reply, rx_reply) = sync::channel::<String>(10);

            if let Ok(stream) = stream {
                let peer = match stream.peer_addr() {
                    Ok(peer) => peer,
                    Err(e) => {
                        warn!("Failed to get peer from console connection: {}", e);
                        return;
                    }
                };
                debug!("Client {:?} connected", peer);

                let tx = tx.clone();
                task::spawn(async move {
                    let (reader, writer) = &mut (&stream, &stream);
                    let reader = io::BufReader::new(reader);
                    let mut lines = reader.lines();
                    while let Some(Ok(line)) = lines.next().await {
                        let line = line.trim();
                        tx.send((line.into(), tx_reply.clone())).await;
                        if let Ok(reply) = rx_reply.recv().await {
                            if let Err(e) = writer.write_all(reply.as_bytes()).await {
                                warn!("Error on console connection {:?}: {}", peer, e);
                                break;
                            }
                        }
                    }
                });
            }
        }
    });
    Ok(rx)
}

/// List versions of currently known containers and applications.
fn versions(state: &mut State) -> Result<String> {
    let versions = state
        .applications()
        .map(|app| app.manifest())
        .map(|manifest| {
            (
                manifest.name.clone(),
                manifest.version.clone(),
                manifest.arch.clone(),
            )
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&versions).context("Failed to encode manifest to json")
}

/// Format something iterateable into a ascii table. The first row of the table input
/// contains the column titles. The table cannot be empty.
fn to_table<T: iter::IntoIterator<Item = I>, I: iter::IntoIterator<Item = S>, S: ToString>(
    table: T,
) -> Result<String> {
    let mut t = Table::new();
    let format = prettytable::format::FormatBuilder::new()
        .column_separator('|')
        .separators(&[], format::LineSeparator::new('-', '+', '+', '+'))
        .padding(1, 1)
        .build();
    t.set_format(format);
    let mut rows = table.into_iter();
    let titles = rows.next().ok_or_else(|| anyhow!("Missing titles"))?.into();
    t.set_titles(titles);
    for r in rows {
        t.add_row(r.into());
    }

    let mut result = vec![];
    t.print(&mut result).context("Failed to format table")?;
    String::from_utf8(result).context("Invalid table content")
}

fn arg_regex(args: &[&str]) -> Result<regex::Regex> {
    match args.len() {
        1 => regex::Regex::new(args[0])
            .with_context(|| format!("Invalid container name regex {}", args[0])),
        0 => regex::Regex::new(".*")
            .with_context(|| format!("Invalid container name regex {}", args[0])),
        _ => Err(anyhow!("Arguments invalid. Use `start PATTERN`",)),
    }
}
