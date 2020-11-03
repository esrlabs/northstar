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

#![deny(clippy::all)]

use crate::runtime::error::Error;
use async_std::{fs::read_to_string, path::PathBuf};
use log::{error, info};
use north::runtime;
use runtime::config::Config;
use std::process;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "north", about = "North")]
struct Opt {
    /// File that contains the north configuration
    #[structopt(short, long, default_value = "north.toml")]
    pub config: PathBuf,

    #[structopt(short, long)]
    /// Print debug logs
    pub debug: bool,
}

#[async_std::main]
async fn main() {
    process::exit(match run().await {
        Ok(()) => 0,
        Err(err) => {
            error!("{}", err);
            1
        }
    })
}

async fn run() -> Result<(), Error> {
    let opt = Opt::from_args();
    let config_string = &read_to_string(&opt.config).await.map_err(|e| Error::Io {
        context: format!("Failed to read configuration file {}", opt.config.display()),
        error: e,
    })?;
    let config: Config = toml::from_str(config_string).map_err(|_| {
        Error::Configuration(format!(
            "Failed to read configuration file {}",
            opt.config.display()
        ))
    })?;

    let log_filter = if opt.debug || config.debug {
        "north=debug"
    } else {
        "north=info"
    };
    logd_logger::builder()
        .parse_filters(log_filter)
        .tag("north")
        .init();

    info!(
        "North v{} ({})",
        env!("VERGEN_SEMVER"),
        env!("VERGEN_SHA_SHORT")
    );

    runtime::run(&config).await
}
