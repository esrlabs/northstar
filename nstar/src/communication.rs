use anyhow::{anyhow, Context, Result};
use byteorder::{BigEndian, ByteOrder};
use itertools::Itertools;
use north::{
    api::{self, Container, Message, Payload, Request, Response},
    manifest::Version,
};
use prettytable::{format, Attr, Cell, Row, Table};
use std::{path::Path, time::Duration};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::OwnedReadHalf,
    sync, time,
};

const RESPONSE_TIMEOUT: Duration = Duration::from_millis(1000);

pub fn start_receiving_from_socket(
    mut reader: OwnedReadHalf,
) -> Result<sync::broadcast::Sender<Response>> {
    let (response_sender, _) = sync::broadcast::channel(100);
    let sender = response_sender.clone();
    let _ = tokio::spawn(async move {
        // TODO listen for shutdown
        loop {
            match receive_reply(&mut reader).await {
                Ok(message) => match message.payload {
                    Payload::Notification(n) => println!("Notification: {:?}", n),
                    Payload::Response(r) => {
                        let _ = response_sender.send(r);
                    }
                    _ => log::warn!("received unexpected payload"),
                },
                Err(e) => {
                    log::warn!("Error receiving from socket: {}", e);
                    break;
                }
            }
        }
    });
    log::debug!("Stopped receiving from socket");
    Ok(sender)
}

pub(crate) async fn run<S: AsyncWriteExt + Unpin>(stream: &mut S, req: Request) -> Result<()> {
    // Send request
    let request_msg = Message {
        id: uuid::Uuid::new_v4().to_string(),
        payload: Payload::Request(req),
    };
    let request = serde_json::to_string(&request_msg).context("Failed to serialize")?;
    let mut buf = [0u8; 4];
    BigEndian::write_u32(&mut buf, request.as_bytes().len() as u32);
    stream
        .write_all(&buf)
        .await
        .context("Failed to write to stream")?;
    stream
        .write_all(request.as_bytes())
        .await
        .context("Failed to write to stream")
    // receive_reply(stream).await
}

async fn receive_reply<S: AsyncReadExt + Unpin>(mut stream: S) -> Result<Message> {
    // Receive reply
    let mut buffer = [0u8; 4];
    stream
        .read_exact(&mut buffer)
        .await
        .context("Failed to read frame length")?;
    let frame_len = BigEndian::read_u32(&buffer) as usize;
    let mut buffer = vec![0; frame_len];
    stream
        .read_exact(&mut buffer)
        .await
        .context("Failed to read frame")?;

    // Deserialize message
    let message: Message = serde_json::from_slice(&buffer).context("Failed to parse reply")?;
    Ok(message)
}

fn render_containers(containers: Vec<Container>) {
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
                    .map(|p| format!("{:?}", Duration::from_nanos(p.uptime)))
                    .unwrap_or_default(),
            ),
        ]));
    }
    table.printstd();
}

pub(crate) async fn containers<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    mut response_receiver: sync::broadcast::Receiver<Response>,
) -> Result<()> {
    run(stream, Request::Containers).await?;
    match time::timeout(RESPONSE_TIMEOUT, response_receiver.recv()).await? {
        Ok(Response::Containers(cs)) => {
            render_containers(cs);
            Ok(())
        }
        Ok(r) => Err(anyhow!(
            "Did receive wrong response for container request: {:?}",
            r
        )),
        Err(e) => Err(anyhow!(
            "Did not receive correct response for container request: {}",
            e
        )),
    }
}

pub(crate) async fn shutdown<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    mut response_receiver: sync::broadcast::Receiver<Response>,
) -> Result<()> {
    run(stream, Request::Shutdown).await?;
    match time::timeout(RESPONSE_TIMEOUT, response_receiver.recv()).await? {
        Ok(Response::Shutdown { result }) => {
            println!("Shutdown response: {:?}", result);
            Ok(())
        }
        Ok(r) => Err(anyhow!(
            "Did receive wrong response for shutdown request: {:?}",
            r
        )),
        Err(e) => Err(anyhow!(
            "Did not receive correct response for shutdown request: {}",
            e
        )),
    }
}

pub(crate) async fn start<'a, S: AsyncWriteExt + Unpin, I: Iterator<Item = &'a str>>(
    mut cmd: I,
    stream: &mut S,
    mut response_receiver: sync::broadcast::Receiver<Response>,
) -> Result<()> {
    let pattern = cmd.next().unwrap_or(".*");
    let re = regex::Regex::new(pattern).context("Invalid regex")?;
    run(stream, Request::Containers).await?;

    match time::timeout(RESPONSE_TIMEOUT, response_receiver.recv()).await? {
        Ok(Response::Containers(containers)) => {
            for container in containers
                .iter()
                .filter(|ref c| c.manifest.init.is_some()) // Filter resource container
                .filter(|ref c| c.process.is_none()) // Filter running containers
                .filter(|ref c| re.is_match(&c.manifest.name))
            {
                run(stream, Request::Start(container.manifest.name.clone())).await?;
                match time::timeout(RESPONSE_TIMEOUT, response_receiver.recv()).await? {
                    Ok(resp) => println!(
                        "Started {}:{}: {:?}",
                        container.manifest.name, container.manifest.version, resp
                    ),
                    Err(e) => println!("Error starting container(s): {}", e),
                }
            }
            Ok(())
        }
        Ok(r) => Err(anyhow!(
            "Did receive wrong response for start request: {:?}",
            r
        )),
        Err(e) => Err(anyhow!(
            "Did not receive correct response for start request: {}",
            e
        )),
    }
}

pub(crate) async fn stop<'a, S: AsyncWriteExt + Unpin, I: Iterator<Item = &'a str>>(
    mut cmd: I,
    stream: &mut S,
    mut response_receiver: sync::broadcast::Receiver<Response>,
) -> Result<()> {
    let pattern = cmd.next().unwrap_or(".*");
    let re = regex::Regex::new(pattern).context("Invalid regex")?;
    run(stream, Request::Containers).await?;

    match time::timeout(RESPONSE_TIMEOUT, response_receiver.recv()).await? {
        Ok(Response::Containers(containers)) => {
            for container in containers
                .iter()
                .filter(|ref c| c.process.is_some()) // Filter not running containers
                .filter(|ref c| re.is_match(&c.manifest.name))
            {
                run(stream, Request::Stop(container.manifest.name.clone())).await?;
                match time::timeout(RESPONSE_TIMEOUT, response_receiver.recv()).await? {
                    Ok(response) => println!(
                        "Stopped {}:{}: {:?}",
                        container.manifest.name, container.manifest.version, response
                    ),
                    Err(e) => println!("Error stopping container(s): {}", e),
                }
            }
            Ok(())
        }
        Ok(r) => Err(anyhow!(
            "Did receive wrong response for stop request: {:?}",
            r
        )),
        Err(e) => Err(anyhow!(
            "Did not receive correct response for stop request: {}",
            e
        )),
    }
}

pub async fn stream_update<S: AsyncWriteExt + Unpin>(
    path_str: Option<&str>,
    mut stream: S,
    mut response_receiver: sync::broadcast::Receiver<Response>,
) -> Result<()> {
    let path_s = path_str.ok_or_else(|| anyhow!("Path to npk missing"))?;
    let path = Path::new(path_s);
    log::debug!("stream_update");
    let file_size = fs::metadata(&path).await?.len();
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("Could not get filename from path"))?
        .to_str()
        .ok_or_else(|| anyhow!("Invalid filename"))?
        .to_string();

    let request_msg = Message {
        id: uuid::Uuid::new_v4().to_string(),
        payload: Payload::Installation(file_size as usize, file_name),
    };
    let request = serde_json::to_string(&request_msg).context("Failed to serialize")?;
    let mut buf = [0u8; 4];
    BigEndian::write_u32(&mut buf, request.as_bytes().len() as u32);
    stream
        .write_all(&buf)
        .await
        .context("Failed to write to stream")?;
    stream
        .write_all(request.as_bytes())
        .await
        .context("Failed to write to stream")?;

    let mut file = File::open(&path).await?;

    let mut buf = [0; 4096];
    let mut sent_bytes = 0usize;
    loop {
        let n = file.read(&mut buf).await?;

        if n == 0 {
            // reached end of file
            break;
        }

        stream
            .write_all(&buf[..n])
            .await
            .context("Failed to write to stream")?;
        sent_bytes += n;
    }

    log::debug!("Sent out update ({} bytes)...waiting for reply", sent_bytes);

    match time::timeout(RESPONSE_TIMEOUT, response_receiver.recv()).await {
        Ok(r) => println!("Installation of {} {:?}", path_s, r),
        Err(e) => println!("Error waiting for installation response: {}", e),
    }
    Ok(())
}

pub(crate) async fn uninstall<'a, S: AsyncWriteExt + Unpin, I: Iterator<Item = &'a str>>(
    mut cmd: I,
    stream: &mut S,
    mut response_receiver: sync::broadcast::Receiver<Response>,
) -> Result<()> {
    log::debug!("uninstall");

    let id = cmd.next().context("Container id missing")?.to_owned();
    let version_str = cmd.next().context("Version missing")?;
    let version = Version::parse(version_str).context("Version has wrong format")?;

    run(stream, Request::Uninstall { name: id, version }).await?;
    match time::timeout(RESPONSE_TIMEOUT, response_receiver.recv()).await? {
        Ok(Response::Uninstall { result }) => {
            match result {
                api::UninstallResult::Success => println!("uninstall succeeded"),
                api::UninstallResult::Error(s) => println!("uninstall failed: {}", s),
            }
            Ok(())
        }
        Ok(r) => Err(anyhow!(
            "Did receive wrong response for uninstall request: {:?}",
            r
        )),
        Err(e) => Err(anyhow!(
            "Did not receive correct response for uninstall request: {}",
            e
        )),
    }
}
