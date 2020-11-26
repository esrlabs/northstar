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
use std::path::PathBuf;
use structopt::StructOpt;

mod inspect;

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
        /// Output directory
        #[structopt(short, long)]
        out: PathBuf,
    },
    /// Unpack Northstar containers
    Unpack {
        /// NPK path
        #[structopt(short, long)]
        npk: PathBuf,
        /// Output directory
        #[structopt(short, long)]
        out: PathBuf,
    },
    /// Print information about a Northstar container
    Inspect {
        /// NPK to inspect
        npk: PathBuf,
    },
    GenKey {
        /// Name of key
        #[structopt(short, long)]
        name: String,
        /// Key directory
        #[structopt(short, long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    env_logger::init();

    match Opt::from_args() {
        Opt::Pack { dir, out, key } => npk::npk::pack(&dir, &out, &key)?,
        Opt::Unpack { npk, out } => npk::npk::unpack(&npk, &out)?,
        Opt::Inspect { npk } => inspect::inspect(&npk)?,
        Opt::GenKey { name, out } => npk::npk::gen_key(&name, &out)?,
    }
    Ok(())
}
