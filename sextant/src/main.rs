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

use anyhow::{anyhow, Error, Result};
use sextant::npk;
use std::{path::PathBuf, str::FromStr};
use structopt::StructOpt;

#[derive(Debug)]
enum Format {
    Text,
    Json,
}

impl FromStr for Format {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Format::Json),
            "text" | "txt" => Ok(Format::Text),
            _ => Err(anyhow!("Invalid format {}", s)),
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(about = "Northstar CLI")]
enum Opt {
    /// Pack Northstar containers
    Pack {
        /// Container source dir
        #[structopt(short, long)]
        dir: PathBuf,
        /// Key file
        #[structopt(short, long)]
        key: PathBuf,
        /// Registry dir
        #[structopt(short, long)]
        out: PathBuf,
        #[structopt(short, long)]
        platform: String,
    },
    /// Unpack Northstar containers
    Unpack {
        /// Container source dir
        #[structopt(short, long)]
        dir: PathBuf,
        #[structopt(short, long)]
        out: PathBuf,
    },
    /// Print information about a Northstar container
    Inspect {
        /// Container to inspect
        #[structopt(short, long)]
        container: PathBuf,
        /// Output format
        #[structopt(short, long)]
        format: Format,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::from_args();
    match opt {
        Opt::Pack {
            dir,
            out,
            key,
            platform,
        } => npk::pack(&dir, &out, &key, &platform),
        _ => {
            unimplemented!();
        }
    }
}
