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

use anyhow::{anyhow, Context, Result};
use futures::{sink::SinkExt, Sink};
use itertools::Itertools;
use log::{info, warn};
use north::api::{self, Container, Message, Notification, Payload, Request, Response};
use npk::manifest::Version;
use prettytable::{format, Attr, Cell, Row, Table};
use std::{env, path::Path, sync::Arc};
use structopt::StructOpt;
use sync::mpsc;
use tokio::{
    fs::File,
    net::TcpStream,
    select,
    stream::{Stream, StreamExt},
    sync::{self, oneshot},
    task, time,
};

mod codec;
mod readline;

const HELP: &str = r"containers:                 List installed containers
shutdown:                   Stop the northstar runtime
start <name>:               Start application
stop <name>:                Stop application
install <file>:             Install/Update npk
uninstall <name> <version>: Unstall npk";

#[derive(Debug, StructOpt)]
#[structopt(name = "nstar", about = "Northstar CLI")]
struct Opt {
    /// File that contains the north configuration
    #[structopt(short, long, default_value = "localhost:4200")]
    host: String,

    /// Output json
    #[structopt(short, long)]
    json: bool,

    /// Run command and exit
    cmd: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Do not overwrite RUST_LOG set from somewhere else ;-)
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "nstar=info");
    }
    pretty_env_logger::init();

    let opt = Opt::from_args();

    // Sync barrier to start the user input after a connection to the runtime
    // is established.
    let barrier = Arc::new(sync::Barrier::new(if opt.cmd.is_empty() { 2 } else { 1 }));

    // User supplied input from the command line
    let (input_tx, mut input_rx) = mpsc::channel(10);

    if opt.cmd.is_empty() {
        // If there's no command supplied via cmd line spawn a task that readlines
        task::spawn(readline::readline(barrier.clone(), input_tx));
    } else {
        // Send the supplied command to the main loop
        let (tx, _rx) = oneshot::channel::<()>();
        input_tx.send((tx, opt.cmd.join(" "))).await.ok();
        drop(input_tx);
    }

    let mut barrier = Some(barrier);

    // Main loop
    'outer: loop {
        // Establish a TCP connection
        info!("Connecting to {}", opt.host);
        let stream = match TcpStream::connect(&opt.host).await {
            Ok(s) => s,
            Err(e) => {
                // If there's a command supplied immediatelly exit with the connection error
                // otherwise we're in interactive mode and retry to connect
                if opt.cmd.is_empty() {
                    info!("Connection failed: {}. Reconnecting in 1s", e);
                    time::sleep(time::Duration::from_secs(1)).await;
                    continue;
                } else {
                    return Err(e).context("Failed to connect");
                }
            }
        };
        info!("Connected to {}", opt.host);
        let (read, write) = stream.into_split();
        let mut framed_read = tokio_util::codec::FramedRead::new(read, codec::Codec::default());
        let mut framed_write = tokio_util::codec::FramedWrite::new(write, codec::Codec::default());

        // Wait until readline is ready on the first start
        if let Some(barrier) = barrier.take() {
            barrier.wait().await;
        }

        let (notification_tx, mut notification_rx) = mpsc::channel::<Notification>(10);
        let (response_tx, mut response_rx) = mpsc::channel::<Response>(10);

        // Spawn a task that reads on the connection and forwards results to the according channel.
        // If this tasks breaks the main loop will get a None on notification_rx or request_tx and
        // break as well.
        task::spawn(async move {
            loop {
                match framed_read.next().await {
                    Some(Ok(message)) => match message.payload {
                        Payload::Request(_) => unreachable!(),
                        Payload::Response(r) => {
                            if response_tx.send(r).await.is_err() {
                                break;
                            }
                        }
                        Payload::Notification(n) => {
                            if notification_tx.send(n).await.is_err() {
                                break;
                            }
                        }
                    },
                    Some(Err(e)) => {
                        warn!("Connection closed: {}", e);
                        break;
                    }
                    None => {
                        info!("Connection closed");
                        break;
                    }
                }
            }
        });

        'inner: loop {
            select! {
                input = input_rx.next() => {
                    let (_done, input) = match input {
                        Some((done, input)) => (done, input),
                        None => break 'outer,
                    };

                    let mut split = input.trim().split_whitespace();
                    match split.next() {
                        Some("help") => println!("{}",  HELP),
                        Some("start") | Some("stop") => {
                            // Request the container list
                            match request_response(&mut framed_write, &mut response_rx, Request::Containers).await {
                                Ok(Some(Response::Containers(c))) => {
                                    match regex::Regex::new(input.split_whitespace().nth(1).unwrap_or(".*")) {
                                        Ok(r) => {
                                            let start = input.starts_with("start");
                                            for name in c.iter()
                                                .filter(|c| c.manifest.init.is_some()) // Filter resource containers
                                                .filter(|c| if start { c.process.is_none() } else { c.process.is_some() }) // Filter running containers
                                                .filter(|c| r.is_match(&c.manifest.name)) // Match argument
                                                .map(|c| c.manifest.name.clone()) {
                                                    if start {
                                                        println!("Starting {}", name);
                                                        match request_response(&mut framed_write, &mut response_rx, Request::Start(name)).await {
                                                            Ok(r) => {
                                                                if opt.json {
                                                                    println!("{}", serde_json::to_string_pretty(&r).unwrap());
                                                                } else {
                                                                    println!("{:?}", r); // TODO
                                                                }
                                                            }
                                                            Err(_) => break 'inner, // Error on connection. Reconnect or exit
                                                        }
                                                    } else {
                                                        println!("Stopping {}", name);
                                                        match request_response(&mut framed_write, &mut response_rx, Request::Stop(name)).await {
                                                            Ok(r) => {
                                                                if opt.json {
                                                                    println!("{}", serde_json::to_string_pretty(&r).unwrap());
                                                                } else {
                                                                    println!("{:?}", r); // TODO
                                                                }
                                                            }
                                                            Err(_) => break 'inner, // Error on connection. Reconnect or exit
                                                        }
                                                    }
                                                }
                                        }
                                        Err(e) => {
                                            warn!("Invalid regex: {:?}", e);
                                        }
                                    }
                                }
                                Ok(r) => {
                                    warn!("Invalid response {:?}. This is runtime internal bug.", r);
                                    break 'inner;
                                }
                                Err(e) => {
                                    warn!("{:?}" , e);
                                    break 'inner;
                                }
                            }
                        }
                        Some("containers") | Some("ls") | Some("list") => {
                            match request_response(&mut framed_write, &mut response_rx, Request::Containers).await {
                                Ok(Some(Response::Containers(c))) => {
                                    if opt.json {
                                        println!("{}", serde_json::to_string_pretty(&c).unwrap());

                                    } else {
                                        format_containers(&c);
                                    }
                                }
                                Ok(_) => panic!("Invalid reponse on container request"),
                                Err(e) => {
                                    warn!("{:?}" , e);
                                    break 'inner;
                                }
                            };
                        }
                        Some("install") => {
                            match split.next() {
                                Some(file) => {
                                    // Get the file and it's len
                                    let file = Path::new(file);
                                    let size = match file.metadata() {
                                        Ok(m) => m.len(),
                                        Err(_) => {
                                            println!("Failed to read metadata from {}", file.display());
                                            continue;
                                        }
                                    };

                                    // Check if npk exists and open
                                    let npk = if !file.exists() {
                                        println!("Failed to find {}", file.display());
                                        continue;
                                    } else {
                                        match File::open(file).await {
                                            Ok(f) => f,
                                            Err(e) => {
                                                println!("Failed to open {}: {}", file.display(), e);
                                                continue;
                                            }
                                        }
                                    };

                                    // Construct a Message with a installation request
                                    // Place the size of the file on disk in the request
                                    let message = codec::Message::Message(Message::new_request(Request::Install(size)));
                                    if let Err(e) = framed_write.send(message).await {
                                        warn!("Stream error: {}", e);
                                        break 'inner;
                                    }
                                    framed_write.flush().await?;

                                    // Read the npk via a ReaderStream that chunks the content
                                    let mut npk = tokio_util::io::ReaderStream::new(npk);
                                    while let Some(r) = npk.next().await {
                                        match r {
                                            // Send the chunk to the stream
                                            Ok(b) => match framed_write.send(codec::Message::Raw(b)).await {
                                                Ok(_) => (),
                                                Err(e) => {
                                                    warn!("Stream error: {}", e);
                                                    break 'inner;
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Failed to read from {}: {}", file.display(), e);
                                                break 'inner;
                                            }
                                        }
                                    }

                                    // Wait for the installation response
                                    match response_rx.next().await {
                                        Some(r) => println!("{:?}", r),
                                        None => {
                                            warn!("Stream error");
                                            break 'inner;
                                        }
                                    }
                                }
                                None => println!("Missing npk argument"),
                            }
                        }
                        Some("uninstall") => {
                            // Get the name: first word after the command
                            let name = match split.next() {
                                Some(name) => name.to_string(),
                                None => {
                                    println!("Missing npk name");
                                    continue;
                                }
                            };
                            // Get the name: second word after the command
                            let version = match split.next() {
                                Some(version) => match Version::parse(version) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        println!("Invalid version {}: {}", version, e);
                                        continue;
                                    }
                                }
                                None => {
                                    println!("Missing npk version");
                                    continue;
                                }
                            };
                            // Request the uninstallation
                            let request = Request::Uninstall { name, version };
                            let response = match request_response(&mut framed_write, &mut response_rx, request).await {
                                Ok(r) => r,
                                Err(e) => {
                                    warn!("{:?}" , e);
                                    break 'inner;
                                }
                            };
                            if opt.json {
                                println!("{}", serde_json::to_string_pretty(&response).unwrap());
                            } else {
                                println!("{:?}", response);
                            }
                        }
                        Some("shutdown") => {
                            if let Err(e) = request_response(&mut framed_write, &mut response_rx, Request::Shutdown).await {
                                warn!("Failed to send shutdown request: {:?}" , e);
                            }
                            // No need to break: If the shutdown was a single command the input_rx channel is closed
                            // and the loop will break
                        }
                        Some(c) => println!("Unknown command {}", c),
                        None => (),
                    }
                }
                notification = notification_rx.next() => {
                    if let Some(notification) = notification {
                        // Print notifications only if not in command mode
                        if opt.cmd.is_empty() {
                            format_notification(&notification, opt.json);
                        }
                    } else {
                        break 'inner;
                    }
                }
            }
        }

        info!("Reconnecting in 1s");
        time::sleep(time::Duration::from_secs(1)).await;
    }

    Ok(())
}

async fn request_response<S, R>(
    mut sink: S,
    mut stream: R,
    request: Request,
) -> Result<Option<Response>>
where
    S: Unpin + Sink<codec::Message>,
    R: Unpin + Stream<Item = Response>,
{
    sink.send(codec::Message::Message(Message::new_request(
        request.clone(),
    )))
    .await
    .map_err(|_| anyhow!("Sink error"))?;
    if request != Request::Shutdown {
        stream
            .next()
            .await
            .context("Stream error")
            .map(Option::Some)
    } else {
        Ok(None)
    }
}

fn format_notification(notification: &Notification, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(&notification).unwrap());
    } else {
        match notification {
            api::Notification::OutOfMemory(name) => println!("{} is out of memory", name),
            api::Notification::ApplicationExited {
                id,
                version,
                exit_info,
            } => {
                println!("Application {}-{} exited with {}", id, version, exit_info);
            }
            api::Notification::Install(name, version) => println!("Installed {}-{}", name, version),
            api::Notification::Uninstalled(name, version) => {
                println!("Uninstallation {}-{}", name, version)
            }
            api::Notification::ApplicationStarted(name, version) => {
                println!("Started {}-{}", name, version)
            }
            api::Notification::ApplicationStopped(name, version) => {
                println!("Stopped {}-{}", name, version)
            }
            api::Notification::Shutdown => println!("Shutdown"),
        }
    }
}

fn format_containers(containers: &[Container]) {
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(Row::new(vec![
        Cell::new("Name").with_style(Attr::Bold),
        Cell::new("Version").with_style(Attr::Bold),
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
    table.printstd();
}
