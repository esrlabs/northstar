//! Northstar package tool

#![deny(clippy::all)]
#![deny(missing_docs)]

use anyhow::Result;
use clap::Parser;
use northstar_runtime::npk::{
    self,
    npk::{CompressionAlgorithm, SquashfsOptions},
};
use std::path::PathBuf;

mod inspect;
mod pack;

/// Northstar package tool
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
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
        compression_algorithm: CompressionAlgorithm,
        /// mksqushfs binary
        #[clap(long, default_value = "mksquashfs")]
        mksquashfs: PathBuf,
        /// Block size used by squashfs (default 128 KiB)
        #[clap(short, long)]
        block_size: Option<u32>,
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
        /// unsquashfs binary
        #[clap(long, default_value = "unsquashfs")]
        unsquashfs: PathBuf,
    },
    /// Print information about a Northstar container
    Inspect {
        #[clap(short, long)]
        short: bool,
        /// NPK to inspect
        npk: PathBuf,
        /// unsquashfs binary
        #[clap(long, default_value = "unsquashfs")]
        unsquashfs: PathBuf,
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
            compression_algorithm,
            mksquashfs,
            block_size,
            clones,
        } => pack::pack(
            &manifest,
            &root,
            &out,
            key.as_deref(),
            SquashfsOptions {
                compression_algorithm,
                mksquashfs,
                block_size,
            },
            clones,
        )?,
        Opt::Unpack {
            npk,
            out,
            unsquashfs,
        } => npk::npk::unpack_with(&npk, &out, &unsquashfs)?,
        Opt::Inspect {
            npk,
            short,
            unsquashfs,
        } => inspect::inspect(&npk, short, &unsquashfs)?,
        Opt::GenKey { name, out } => npk::npk::generate_key(&name, &out)?,
    }
    Ok(())
}
