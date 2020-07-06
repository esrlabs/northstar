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

use async_std::path::PathBuf;
use itertools::Itertools;
use std::{fmt, path::Path};
use structopt::StructOpt;

const DEFAULT_CONSOLE_ADDRESS: &str = "127.0.0.1:4242";

lazy_static::lazy_static! {
    #[derive(Debug)]
    pub static ref SETTINGS: Settings = {
        let opt = CliOptions::from_args();
        let mut settings = config::Config::default();

        // Read config file
        // Try the command line config file and fall back to north.toml
        if let Some(config) = opt.config {
            settings.merge(config::File::with_name(&config)).expect("Failed to read configuration");
        } else {
            let config = Path::new("north.toml");
            if config.is_file() {
                settings.merge(config::File::with_name(&config.display().to_string())).expect("Failed to read configuration");
            } else {
                panic!("Failed to find default configuration res/north.toml");
            }
        }

        // Read environment
        settings.merge(config::Environment::with_prefix("NORTH")).expect("Failed to read environment");

        let container_dirs = opt.container_dir.unwrap_or_else(|| {
            let dir: Vec<String> = settings.get("container_dirs").expect("Missing container directories in configuration");
            dir.iter().map(PathBuf::from).collect()
        });
        let run_dir = opt.run_dir.unwrap_or_else(|| {
            let dir: String = settings.get("run_dir").expect("Missing run dir in configuration");
            PathBuf::from(dir)
        });
        let data_dir = opt.data_dir.unwrap_or_else(|| {
            let dir: String = settings.get("data_dir").expect("Missing data dir in configuration");
            PathBuf::from(dir)
        });
        let console_address = opt.console_address.unwrap_or_else(|| {
            settings.get("console_address").unwrap_or_else(|_| DEFAULT_CONSOLE_ADDRESS.into())
        });
        let disable_network_namespaces = opt.disable_network_namespaces || settings.get("disable_network_namespaces").unwrap_or(false);
        let global_data_dir = opt.disable_network_namespaces || settings.get("global_data_dir").unwrap_or(false);

        Settings {
            debug: opt.debug,
            container_dirs,
            run_dir,
            data_dir,
            console_address,
            disable_network_namespaces,
            global_data_dir,
        }
    };
}

#[derive(Debug, StructOpt)]
#[structopt(name = "north", about = "North")]
struct CliOptions {
    /// Directory containing images in container format
    #[structopt(short, long)]
    pub config: Option<String>,

    #[structopt(short, long)]
    /// Print debug logs
    pub debug: bool,

    /// Directory containing images in container format
    #[structopt(long)]
    pub container_dir: Option<Vec<PathBuf>>,

    /// Directory with unpacked containers
    #[structopt(long)]
    pub run_dir: Option<PathBuf>,

    /// Directory where rw data of container shall be stored
    #[structopt(long)]
    pub data_dir: Option<PathBuf>,

    /// Console address
    #[structopt(long)]
    pub console_address: Option<String>,

    /// Do not use and setup networknamespaces
    #[structopt(long)]
    pub disable_network_namespaces: bool,

    /// Share the rw data location between containers. Do not setup
    /// a dedicated data dir per container.
    #[structopt(long)]
    pub global_data_dir: bool,
}

#[derive(Debug)]
pub struct Settings {
    pub debug: bool,
    pub container_dirs: Vec<PathBuf>,
    pub run_dir: PathBuf,
    pub data_dir: PathBuf,
    pub console_address: String,
    pub disable_network_namespaces: bool,
    pub global_data_dir: bool,
}

impl fmt::Display for Settings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "debug: {:?}", self.debug)?;
        writeln!(
            f,
            "container_dirs: {}",
            self.container_dirs
                .iter()
                .map(|d| d.display().to_string())
                .join(", "),
        )?;
        writeln!(f, "run_dir: {}", self.run_dir.display())?;
        writeln!(f, "data_dir: {}", self.data_dir.display())?;
        writeln!(f, "console_address: {}", self.console_address)?;
        writeln!(
            f,
            "disable_network_namespaces: {}",
            self.disable_network_namespaces
        )?;
        writeln!(f, "global_data_dir: {}", self.global_data_dir)
    }
}
