//! Northstar package tool

#![deny(clippy::all)]
#![deny(missing_docs)]

use anyhow::Result;
use northstar::npk;
use std::path::PathBuf;
use structopt::StructOpt;

mod inspect;
mod pack;

#[derive(Debug, StructOpt)]
#[structopt(about = "Northstar CLI")]
enum Opt {
    /// Pack Northstar containers
    Pack {
        /// Manifest path
        #[structopt(short, long)]
        manifest: PathBuf,
        /// Container source directory
        #[structopt(short, long)]
        root: PathBuf,
        /// Key file
        #[structopt(short, long)]
        key: Option<PathBuf>,
        /// Output directory
        #[structopt(short, long)]
        out: PathBuf,
        /// Compression algorithm to use in squashfs (default gzip)
        #[structopt(short, long, default_value = "gzip")]
        comp: npk::npk::CompressionAlgorithm,
        /// Block size used by squashfs (default 128 KiB)
        #[structopt(short, long)]
        block_size: Option<u32>,
        /// Create n clones of the container
        #[structopt(long)]
        clones: Option<u32>,
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
        #[structopt(short, long)]
        short: bool,
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
        Opt::Pack {
            manifest,
            root,
            out,
            key,
            comp,
            block_size,
            clones,
        } => pack::pack(
            &manifest,
            &root,
            &out,
            key.as_deref(),
            comp,
            block_size,
            clones,
        )?,
        Opt::Unpack { npk, out } => npk::npk::unpack(&npk, &out)?,
        Opt::Inspect { npk, short } => inspect::inspect(&npk, short)?,
        Opt::GenKey { name, out } => npk::npk::generate_key(&name, &out)?,
    }
    Ok(())
}
