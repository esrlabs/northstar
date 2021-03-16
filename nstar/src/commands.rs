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

use anyhow::Result;
use colored::Colorize;
use npk::manifest::Version;
use std::path::PathBuf;
use structopt::{
    clap::{self, AppSettings},
    StructOpt,
};

#[derive(StructOpt)]
pub enum Northstar {
    #[structopt(about = "List available containers", alias = "ls", alias = "list")]
    Containers,
    #[structopt(about = "List configured repositories", alias = "repos")]
    Repositories,
    #[structopt(about = "Mount a container")]
    Mount {
        #[structopt(help = "Name of the container")]
        name: String,
        #[structopt(help = "Version of the container")]
        version: Version,
    },
    #[structopt(about = "Unmount a container")]
    Umount {
        #[structopt(help = "Name of the container")]
        name: String,
        #[structopt(help = "Version of the container")]
        version: Version,
    },
    #[structopt(about = "Start a container")]
    Start {
        #[structopt(help = "Name of the container")]
        name: String,
        #[structopt(help = "Version of the container")]
        version: Version,
    },
    #[structopt(about = "Stop a container")]
    Stop {
        #[structopt(help = "Name of the container")]
        name: String,
        #[structopt(help = "Version of the container")]
        version: Version,
        #[structopt(help = "Timeout", default_value = "5")]
        timeout: u64,
    },
    #[structopt(about = "Install a container")]
    Install {
        #[structopt(help = "Path to the .npk file")]
        npk: PathBuf,
        #[structopt(help = "Target repository")]
        repo_id: String,
    },
    #[structopt(about = "Uninstall a container")]
    Uninstall {
        #[structopt(help = "Name of the container")]
        name: String,
        #[structopt(help = "Container version")]
        version: Version,
    },
    #[structopt(about = "Shutdown Northstar")]
    Shutdown,
}

#[derive(StructOpt)]
pub enum Prompt {
    #[structopt(about = "Print help", alias = "h", alias = "?")]
    Help,
    #[structopt(about = "Quit", alias = "q", alias = "exit")]
    Quit,
}

#[derive(StructOpt)]
pub struct NstarOpt {
    #[structopt(
        help = "Northstar's instance url",
        default_value = "tcp://localhost:4200"
    )]
    pub host: String,
    #[structopt(
        short,
        long,
        help = "If present, print Northstar's response in JSON format"
    )]
    pub json: bool,
    #[structopt(subcommand)]
    pub command: Option<Northstar>,
}

#[derive(StructOpt)]
pub enum PromptCommand {
    #[structopt(flatten)]
    Northstar(Northstar),
    #[structopt(flatten)]
    Prompt(Prompt),
}

/// Used  to validate the user input in the interactive mode
pub struct PromptParser<'a, 'b> {
    app: clap::App<'a, 'b>,
}

impl<'a, 'b> PromptParser<'a, 'b> {
    pub fn new() -> Self {
        Self {
            app: PromptCommand::clap()
                .settings(&[
                    AppSettings::SubcommandRequiredElseHelp,
                    AppSettings::VersionlessSubcommands,
                    AppSettings::DisableVersion,
                    AppSettings::DisableHelpFlags,
                    AppSettings::ColoredHelp,
                ])
                .template("\n{subcommands}\n")
                .global_settings(&[AppSettings::NoBinaryName, AppSettings::InferSubcommands]),
        }
    }

    /// Use to parse the user input
    pub fn parse(&mut self, input: &str) -> clap::Result<PromptCommand> {
        let result = self
            .app
            .get_matches_from_safe_borrow(input.split_whitespace())
            .map(|m| PromptCommand::from_clap(&m));

        // Treat specially the top level errors
        if let Err(ref e) = result {
            if matches!(
                e.kind,
                clap::ErrorKind::InvalidSubcommand
                    | clap::ErrorKind::UnrecognizedSubcommand
                    | clap::ErrorKind::UnknownArgument
            ) {
                return Err(clap::Error::with_description(
                    &format!(
                        "Invalid input, use {} to list the available commands",
                        "help".blue()
                    ),
                    clap::ErrorKind::InvalidSubcommand,
                ));
            }
        }

        result
    }

    /// Print prompt command help
    pub fn print_help<W: std::io::Write>(&self, output: &mut W) -> Result<()> {
        self.app.write_help(output)?;
        output.flush()?;
        Ok(())
    }
}
