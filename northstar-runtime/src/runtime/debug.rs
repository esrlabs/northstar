use crate::{
    common::container::Container,
    runtime::{config::Config, error::Error, runtime::Pid},
};
use anyhow::{Context, Result};
use async_stream::stream;
use futures::StreamExt;
use log::{error, info};
use std::process::Stdio;
use tokio::{
    io::{self, AsyncBufReadExt},
    process::Command,
    select,
    task::{self},
};

pub(crate) async fn start(config: &Config, container: &Container, pid: Pid) -> Result<(), Error> {
    let container = container.to_string();

    for command in config.debug.iter().flat_map(|c| &c.commands) {
        let command = command
            .replace("<PID>", pid.to_string().as_str())
            .replace("<CONTAINER>", container.as_str());
        info!("Spawning debug command: {command}");
        let mut argv = command.split_whitespace();
        let cmd = argv.next().context("invalid debug command")?;
        let mut child = Command::new(cmd)
            .args(argv)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn debug command")?;

        let container = container.clone();
        task::spawn(async move {
            let stderr = child.stderr.take().expect("failed to get stderr of strace");
            let stdout = child.stdout.take().expect("failed to get stdout of strace");

            // Merge stdout and stderr.
            let mut lines = Box::pin(stream! {
                let mut stdout = io::BufReader::new(stdout).lines();
                let mut stderr = io::BufReader::new(stderr).lines();
                loop {
                    select! {
                        line = stdout.next_line() => yield line,
                        line = stderr.next_line() => yield line,
                    }
                }
            });

            loop {
                select! {
                    result = child.wait() => {
                        match result {
                            Ok(status) => info!(target: &container, "command {command} exited with {}", status),
                            Err(e) => error!(target: &container, "command {command} failed: {}", e),
                        }
                        break;
                    },
                    result = lines.next() => {
                        match result {
                            Some(Ok(Some(line))) => info!(target: &container, "{}", line),
                            Some(Err(e)) => {
                                error!(target: &container, "failed to forward strace output: {}", e);
                                break;
                            }
                            _ => break,
                        }
                    }
                }
            }

            Result::<(), anyhow::Error>::Ok(())
        });
    }
    Ok(())
}
