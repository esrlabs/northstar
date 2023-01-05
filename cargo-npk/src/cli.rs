use std::{fmt::Display, path::PathBuf};

use clap::{Parser, ValueEnum};
use northstar_runtime::npk::npk::Compression as NpkCompressionAlgorithm;

#[derive(Parser)]
#[group(skip)]
pub struct Command {
    #[clap(subcommand)]
    pub npk: NpkCommand,
}

#[derive(clap::Subcommand)]
pub enum NpkCommand {
    /// Build npks
    Npk {
        #[clap(subcommand)]
        cmd: NpkSubCommand,
    },
}

#[derive(Parser)]
#[group(skip)]
pub struct Args {
    #[clap(flatten)]
    pub subcommand_args: cargo_subcommand::Args,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Compression {
    Gzip,
    Lzma,
    Lzo,
    Xz,
    Zstd,
}

impl From<Compression> for NpkCompressionAlgorithm {
    fn from(c: Compression) -> Self {
        match c {
            Compression::Gzip => NpkCompressionAlgorithm::Gzip,
            Compression::Lzma => NpkCompressionAlgorithm::Lzma,
            Compression::Lzo => NpkCompressionAlgorithm::Lzo,
            Compression::Xz => NpkCompressionAlgorithm::Xz,
            Compression::Zstd => NpkCompressionAlgorithm::Zstd,
        }
    }
}

impl Display for Compression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("{self:?}").to_lowercase())
    }
}

#[derive(clap::Subcommand)]
#[clap(trailing_var_arg = true)]
#[group(skip)]
#[allow(clippy::large_enum_variant)]
pub enum NpkSubCommand {
    /// Compile the current package and create an apk
    Pack {
        #[clap(flatten)]
        args: Args,
        /// Northstar key.
        #[clap(long("key"))]
        key: Option<PathBuf>,
        /// Compression algorithm.
        #[clap(long("compression"), default_value = "gzip")]
        compression: Compression,
        /// Block size.
        #[clap(long("block-size"))]
        block_size: Option<u32>,
        /// Path to mksquashfs binary.
        #[clap(long("mksquashfs"))]
        mksquashfs: Option<PathBuf>,
        /// Create n clones of the container.
        #[arg(long)]
        clones: Option<u32>,
        /// Coloring
        #[clap(long("color"), default_value = "auto")]
        color: ColorChoice,
        /// Output directory
        #[clap(long("out"))]
        out: Option<PathBuf>,
    },
    /// Print the version of cargo-apk
    Version,
}
