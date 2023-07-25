//! Northstar package tool

#![deny(clippy::all)]
#![deny(missing_docs)]

use anyhow::Result;
use clap::{Parser, ValueEnum};
use northstar_runtime::npk::{
    self,
    npk::{Compression as NpkCompression, SquashfsOptions},
};
use std::path::PathBuf;

mod inspect;
mod pack;

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Compression {
    None,
    #[default]
    Gzip,
    Lzma,
    Lzo,
    Xz,
    Zstd,
}

impl From<Compression> for NpkCompression {
    fn from(c: Compression) -> Self {
        match c {
            Compression::None => NpkCompression::None,
            Compression::Gzip => NpkCompression::Gzip,
            Compression::Lzma => NpkCompression::Lzma,
            Compression::Lzo => NpkCompression::Lzo,
            Compression::Xz => NpkCompression::Xz,
            Compression::Zstd => NpkCompression::Zstd,
        }
    }
}

/// Northstar package tool
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
enum Opt {
    /// Pack Northstar containers
    Pack {
        /// Path to manifest in yaml, toml or json.
        #[arg(short, long("manifest-path"))]
        manifest_path: PathBuf,
        /// Container source directory
        #[arg(short, long)]
        root: Option<PathBuf>,
        /// Key file
        #[arg(short, long)]
        key: Option<PathBuf>,
        /// Output directory
        #[arg(short, long)]
        out: PathBuf,
        /// Compression algorithm to use in squashfs (default gzip)
        #[arg(short, long, default_value = "gzip")]
        compression: Compression,
        /// mksqushfs binary
        #[arg(long, default_value = "mksquashfs")]
        mksquashfs: PathBuf,
        /// Block size used by squashfs (default 128 KiB)
        #[arg(short, long)]
        block_size: Option<u32>,
        /// Create n clones of the container.
        #[arg(long)]
        clones: Option<u32>,
    },
    /// Unpack Northstar containers
    Unpack {
        /// NPK path
        #[arg(short, long)]
        npk: PathBuf,
        /// Output directory
        #[arg(short, long)]
        out: PathBuf,
        /// unsquashfs binary
        #[arg(long, default_value = "unsquashfs")]
        unsquashfs: PathBuf,
    },
    /// Print information about a Northstar container
    Inspect {
        #[arg(short, long)]
        short: bool,
        /// NPK to inspect
        npk: PathBuf,
        /// unsquashfs binary
        #[arg(long, default_value = "unsquashfs")]
        unsquashfs: PathBuf,
    },
    GenKey {
        /// Name of key
        #[arg(short, long)]
        name: String,
        /// Key directory
        #[arg(short, long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    env_logger::init();

    match Opt::parse() {
        Opt::Pack {
            manifest_path,
            root,
            out,
            key,
            compression,
            mksquashfs,
            block_size,
            clones,
        } => {
            // Without a root argument create an empty tempdir that serves as root.
            let (root, _tempdir) = if let Some(root) = root {
                (root, None)
            } else {
                let tempdir = tempfile::tempdir()?;
                (tempdir.path().to_owned(), Some(tempdir))
            };
            let squashfs_options = &SquashfsOptions {
                compression: compression.into(),
                mksquashfs,
                block_size,
            };

            pack::pack(
                &manifest_path,
                &root,
                &out,
                key.as_deref(),
                squashfs_options,
                clones,
            )?
        }
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
