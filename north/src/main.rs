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

use anyhow::Result;
use async_std::{fs::read_to_string, path::PathBuf};
use log::info;
use north::runtime;
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
async fn main() -> Result<()> {
    let opt = Opt::from_args();

    let log_filter = if opt.debug {
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

    let config = toml::from_str(&read_to_string(&opt.config).await?)?;

    runtime::run(&config).await
}
