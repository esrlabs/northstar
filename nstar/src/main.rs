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

use anyhow::{Context, Result};
use colored::Colorize;
use commands::{parse_prompt, print_help, Northstar, NstarOpt, Prompt, PromptCommand};
use futures::StreamExt;
use northstar::api::{
    self,
    client::Client,
    model::{Container, Request, Response},
};
use std::{io::Write, path::Path};
use structopt::StructOpt;
use tokio::{select, time};

mod commands;
mod pretty;
mod terminal;

/// Same stuff but returns a json string
async fn send_request(
    client: &mut Client,
    command: Northstar,
) -> Result<Response, api::client::Error> {
    let request = match command {
        Northstar::Containers => Request::Containers,
        Northstar::Repositories => Request::Repositories,
        Northstar::Mount { name, version } => Request::Mount(vec![Container::new(name, version)]),
        Northstar::Umount { name, version } => Request::Umount(Container::new(name, version)),
        Northstar::Start { name, version } => Request::Start(Container::new(name, version)),
        Northstar::Stop {
            name,
            version,
            timeout,
        } => Request::Stop(Container::new(name, version), timeout),
        Northstar::Install { npk, repo_id } => {
            let npk = Path::new(&npk).canonicalize()?;
            return match client.install(&npk, &repo_id).await {
                Ok(()) => Ok(Response::Ok(())),
                Err(e) => Ok(Response::Err(api::model::Error::Npk(e.to_string()))),
            };
        }
        Northstar::Uninstall { name, version } => Request::Uninstall(Container::new(name, version)),
        Northstar::Shutdown => Request::Shutdown,
    };

    client.request(request).await
}

/// Tries to connect to northstar indefinitely
async fn try_connect<W: Write>(output: &mut W, url: &url::Url) -> Result<api::client::Client> {
    loop {
        match api::client::Client::new(url)
            .await
            .context(format!("Failed to connect to {}", url))
        {
            Err(e) => writeln!(output, "{}", e.to_string().red())?,
            client => break client,
        }
        time::sleep(time::Duration::from_secs(1)).await;
        writeln!(output, "Reconnecting...")?;
    }
}

async fn print_response<W: Write>(mut out: &mut W, response: Response, json: bool) -> Result<()> {
    if json {
        serde_json::to_writer(&mut out, &response)?;
        out.write_all(&[b'\n'])
            .context("Failed to print json response")
    } else {
        pretty::print_response(out, response).await
    }
}

fn main() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let res = runtime.block_on(async move {
        let opt = NstarOpt::from_args();
        let url = url::Url::parse(&opt.host)?;

        // Open connection to northstar
        let mut client = try_connect(&mut std::io::stdout(), &url).await?;

        // Execute the provided command and exit
        if let Some(command) = opt.command {
            let response = send_request(&mut client, command).await?;
            return print_response(&mut std::io::stdout(), response, opt.json).await;
        }

        // Interactive mode
        let (mut terminal, mut input) = terminal::Terminal::new()?;
        loop {
            writeln!(terminal, "Connected to {}", &url)?;
            loop {
                select! {
                    notification = client.next() => {
                        if let Some(Ok(n)) = notification {
                            pretty::notification(&mut terminal, &n);
                        } else {
                            break;
                        }
                    },
                    Some(input) = input.next() => {
                        let input: String = match input {
                            terminal::UserInput::Line(line) => line,
                            terminal::UserInput::Eof => return Ok(()),
                        };

                        match parse_prompt(&input) {
                            Ok(PromptCommand::Prompt(cmd)) => match cmd {
                                Prompt::Help => print_help(&mut terminal)?,
                                Prompt::Quit => {
                                    writeln!(&mut terminal, "bye!")?;
                                    return Ok(())
                                },
                            },
                            Ok(PromptCommand::Northstar(cmd)) => {
                                match send_request(&mut client, cmd).await {
                                    Ok(response) => print_response(&mut terminal, response, opt.json).await?,
                                    // break the loop and try to reconnect
                                    Err(api::client::Error::Stopped) => break,
                                    Err(e) => writeln!(terminal, "{}: {}", "client error".red(), e)?,
                                };
                            },
                            Err(e) => writeln!(terminal, "{}", e.message)?
                        };
                    }
                    else => break,
                }
            }

            // Try to reconnect
            writeln!(terminal, "Disconnected, trying to reconnect")?;
            client = try_connect(&mut terminal, &url).await?;
        }
    });

    // Shutdown the runtime
    // Also stops the terminal blocked reading from stdin
    runtime.shutdown_background();

    res
}
