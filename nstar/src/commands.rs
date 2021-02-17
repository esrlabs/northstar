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

use npk::manifest::Version;
use std::path::PathBuf;
use structopt::{
    clap::{AppSettings, Result},
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

/// Used to parse the input form the interactive prompt
pub fn parse_prompt(input: &str) -> Result<PromptCommand> {
    PromptCommand::clap()
        .settings(&[
            AppSettings::NoBinaryName,
            AppSettings::ColoredHelp,
            AppSettings::SubcommandRequired,
            AppSettings::DisableHelpFlags,
            AppSettings::DisableVersion,
            AppSettings::DisableHelpSubcommand,
        ])
        .get_matches_from_safe(input.split_whitespace())
        .map(|m| PromptCommand::from_clap(&m))
}

/// Print prompt command help
pub fn print_help<W: std::io::Write>(output: &mut W) -> Result<()> {
    writeln!(output)?;
    PromptCommand::clap()
        .settings(&[
            AppSettings::NoBinaryName,
            AppSettings::ColoredHelp,
            AppSettings::SubcommandRequired,
            AppSettings::DisableHelpFlags,
            AppSettings::DisableVersion,
            AppSettings::DisableHelpSubcommand,
        ])
        .template("{subcommands}\n")
        .write_help(output)
}
