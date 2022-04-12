//! Northstar package tool

#![deny(clippy::all)]
#![deny(missing_docs)]

use anyhow::Result;
use clap::Parser;
use northstar::npk;
use std::path::PathBuf;

mod inspect;
mod pack;

#[derive(Debug, Parser)]
#[clap(about = "Northstar CLI")]
enum Opt {
    /// Pack Northstar containers
    Pack {
        /// Manifest path
        #[clap(short, long)]
        manifest: PathBuf,
        /// Container source directory
        #[clap(short, long)]
        root: PathBuf,
        /// Key file
        #[clap(short, long)]
        key: Option<PathBuf>,
        /// Output directory
        #[clap(short, long)]
        out: PathBuf,
        /// Compression algorithm to use in squashfs (default gzip)
        #[clap(short, long, default_value = "gzip")]
        comp: npk::npk::CompressionAlgorithm,
        /// Block size used by squashfs (default 128 KiB)
        #[clap(short, long)]
        block_size: Option<u32>,
        // Author meta information
        #[clap(short, long)]
        author: Option<String>,
        /// Create n clones of the container
        #[clap(long)]
        clones: Option<u32>,
    },
    /// Unpack Northstar containers
    Unpack {
        /// NPK path
        #[clap(short, long)]
        npk: PathBuf,
        /// Output directory
        #[clap(short, long)]
        out: PathBuf,
    },
    /// Print information about a Northstar container
    Inspect {
        #[clap(short, long)]
        short: bool,
        /// NPK to inspect
        npk: PathBuf,
    },
    GenKey {
        /// Name of key
        #[clap(short, long)]
        name: String,
        /// Key directory
        #[clap(short, long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    env_logger::init();

    match Opt::parse() {
        Opt::Pack {
            manifest,
            root,
            out,
            key,
            comp,
            block_size,
            author,
            clones,
        } => pack::pack(
            &manifest,
            &root,
            &out,
            key.as_deref(),
            comp,
            block_size,
            author.as_deref(),
            clones,
        )?,
        Opt::Unpack { npk, out } => npk::npk::unpack(&npk, &out)?,
        Opt::Inspect { npk, short } => inspect::inspect(&npk, short)?,
        Opt::GenKey { name, out } => npk::npk::generate_key(&name, &out)?,
    }
    Ok(())
}
