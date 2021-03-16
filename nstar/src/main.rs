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

async fn create_client(host: &str) -> Result<api::client::Client> {
    api::client::Client::new(&url::Url::parse(host)?)
        .await
        .context(format!("Failed to establish connection to {}", host))
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

#[tokio::main]
async fn main() -> Result<()> {
    let opt = NstarOpt::from_args();
    let mut client = create_client(&opt.host).await?;

    // Execute the provided command and exit
    if let Some(command) = opt.command {
        let response = send_request(&mut client, command).await?;
        return print_response(&mut std::io::stdout(), response, opt.json).await;
    }

    // Interactive mode
    let (mut terminal, mut input) = terminal::Terminal::new()?;
    'outer: loop {
        writeln!(terminal, "Connected to {}", &opt.host)?;

        loop {
            select! {
                notification = client.next() => {
                    if let Some(Ok(n)) = notification {
                        pretty::notification(&mut terminal, &n);
                    } else {
                        break;
                    }
                }
                input = input.next() => {
                    let input: &str = if input.is_some() {
                        input.as_deref().unwrap()
                    } else {
                        break 'outer;
                    };
                    match parse_prompt(input) {
                        Ok(PromptCommand::Prompt(cmd)) => match cmd {
                            Prompt::Help => print_help(&mut terminal)?,
                            Prompt::Quit => break 'outer,
                        },
                        Ok(PromptCommand::Northstar(cmd)) => {
                            match send_request(&mut client, cmd).await {
                                Ok(response) => print_response(&mut terminal, response, opt.json).await?,
                                // break the loop and try to reconnect
                                Err(api::client::Error::Stopped) => break,
                                Err(e) => writeln!(&mut terminal, "{}: {}", "client error".red(), e)?,
                            };
                        },
                        Err(e) => writeln!(&mut terminal, "{}", e.message)?
                    };
                }
            }
        }

        writeln!(terminal, "Disconnected")?;
        time::sleep(time::Duration::from_secs(1)).await;

        // Try to reconnect
        client = create_client(&opt.host).await?;
    }
    Ok(())
}
