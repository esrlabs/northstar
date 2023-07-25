use anyhow::{anyhow, bail, Context};
use cargo_metadata::MetadataCommand;
use cli::{ColorChoice, Compression};
use human_bytes::human_bytes;
use humantime::format_duration;
use std::{
    env::current_dir,
    ffi::OsString,
    fs, io,
    io::Write,
    path::PathBuf,
    process::{self},
    time,
};
use termcolor::{Color, ColorSpec, StandardStream, WriteColor};

use std::path::Path;

use anyhow::Result;
use cargo_subcommand::{Profile, Subcommand};
use clap::Parser;
use northstar_runtime::npk::npk::{NpkBuilder, SquashfsOptions};

use crate::metadata::Metadata;

mod cli;
mod metadata;

const CROSS: &str = "cross";
const CARGO: &str = "cargo";
const MKSQUASHFS: &str = "mksquashfs";

pub fn npk<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone + std::fmt::Debug + ToString,
{
    let cli::Command {
        npk: cli::NpkCommand::Npk { cmd },
    } = cli::Command::parse_from(args);

    match cmd {
        cli::NpkSubCommand::Pack {
            args,
            key,
            compression,
            block_size,
            mksquashfs,
            clones,
            color,
            out,
        } => {
            let cmd = Subcommand::new(args.subcommand_args)?;
            pack(
                cmd,
                key.as_deref(),
                compression,
                block_size,
                mksquashfs,
                clones,
                color,
                out.as_deref(),
            )
        }
        cli::NpkSubCommand::Version => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn pack(
    cmd: Subcommand,
    key: Option<&Path>,
    compression: Compression,
    block_size: Option<u32>,
    mksquashfs: Option<PathBuf>,
    clones: Option<u32>,
    color: ColorChoice,
    out_dir: Option<&Path>,
) -> Result<()> {
    let start = time::Instant::now();
    let mut stdout = stdout(color);
    let quiet = cmd.quiet();
    let mut log = move |tag: &str, msg: &str| -> Result<()> {
        if !quiet {
            stdout.set_color(ColorSpec::new().set_bold(true).set_fg(Some(Color::Green)))?;
            write!(stdout, "{tag:>12} ")?;
            stdout.reset()?;
            writeln!(stdout, "{msg}")?;
        }
        Ok(())
    };

    let target = cmd.target().unwrap_or_else(|| cmd.host_triple());

    if cmd.artifacts().len() > 1 {
        bail!("crates with multiple artifacts are unsupported");
    }

    // TODO: feature support.
    let cargo_metadata = MetadataCommand::new()
        .manifest_path(cmd.manifest())
        .exec()?;

    // Parse package.
    let package = cargo_metadata
        .packages
        .iter()
        .find(|p| p.manifest_path == cmd.manifest())
        .ok_or_else(|| anyhow!("failed to find package"))?;

    // Northstar manifest and metadata.
    let metadata = Metadata::deserilize(cmd.manifest(), &package.metadata, target)?;
    let northstar_manifest = &metadata.manifest;

    // Build.
    log(
        "Building",
        &format!(
            "{} from {}{}",
            package.name,
            cmd.manifest().display(),
            cmd.target().map(|t| format! {" [{t}]"}).unwrap_or_default()
        ),
    )?;
    let executable = build(&cmd, target, metadata.use_cross)?;

    // Rootfs.
    let tempdir = tempfile::TempDir::new().context("failed to create tempdir")?;
    let root = tempdir.path().to_owned();
    rootfs(&root, &metadata, &executable)?;

    // Pack.
    let squashfs_opts = SquashfsOptions {
        compression: compression.into(),
        block_size,
        mksquashfs: mksquashfs.unwrap_or_else(|| PathBuf::from(MKSQUASHFS)),
    };

    // If the target matches the host tripple there's not triple subdir in target.
    let target = if cmd.target() == Some(cmd.host_triple()) {
        None
    } else {
        cmd.target()
    };

    // Place the npk in `out_dir` if proficed - otherwise calculate the build dir.
    let out = if let Some(out_dir) = out_dir {
        if !out_dir.is_dir() {
            fs::create_dir_all(out_dir)
                .with_context(|| format!("failed to create {}", out_dir.display()))?;
        }
        out_dir.to_owned()
    } else {
        cmd.build_dir(target)
    };

    let builder = NpkBuilder::default().root(&root, Some(&squashfs_opts));
    let builder = if let Some(key) = key {
        builder.key(key)
    } else {
        builder
    };

    if let Some(clones) = clones {
        let name = northstar_manifest.name.clone();
        let num = clones.to_string().chars().count();
        let mut manifest = northstar_manifest.clone();
        for n in 0..clones {
            manifest.name = format!("{name}-{n:0num$}")
                .try_into()
                .context("failed to parse name")?;
            let (npk, npk_size) = builder.clone().manifest(&manifest).to_dir(&out)?;
            let npk_size = human_bytes(npk_size as f64);
            let msg = format!("{} [{}, {}]", npk.display(), npk_size, compression);
            log("Packed", &msg)?;
        }
        let duration = format_duration(time::Duration::from_secs(start.elapsed().as_secs()));
        log("Finished", &format!("{clones} clones in {duration}"))?;
    } else {
        let (npk, npk_size) = builder.manifest(northstar_manifest).to_dir(&out)?;
        let npk_size = human_bytes(npk_size as f64);
        let duration = format_duration(time::Duration::from_secs(start.elapsed().as_secs()));
        let msg = format!(
            "{} [{}, {}] in {}",
            npk.display(),
            npk_size,
            compression,
            duration
        );
        log("Packed", &msg)?;
    }

    Ok(())
}

fn build(subcommand: &Subcommand, target: &str, use_cross: bool) -> Result<PathBuf> {
    // Select "cargo" and manifest path
    let (cargo, cargo_manifest) = if use_cross {
        (
            CROSS,
            // Cross requires a relative dir in order to map pathes
            // into a container.
            subcommand.manifest().strip_prefix(current_dir()?)?,
        )
    } else {
        (CARGO, subcommand.manifest())
    };

    let mut command = process::Command::new(cargo);

    command.arg("build");

    let manifest_path = cargo_manifest.display().to_string();
    command.args(["--manifest-path", &manifest_path]);

    let target_dir = subcommand.target_dir().display().to_string();
    command.args(["--target-dir", &target_dir]);

    if subcommand.quiet() {
        command.args(["--quiet", target]);
    }
    if target != subcommand.host_triple() {
        command.args(["--target", target]);
    }
    if subcommand.profile() == &Profile::Release {
        command.arg("--release");
    }
    // Spawn cargo/cross and wait for the binary to be finished.
    if !command
        .spawn()
        .context("failed to spawn cargo/cross")?
        .wait()?
        .success()
    {
        bail!("failed to run cargo");
    }

    let artifact = subcommand.artifacts().first().expect("missing artifact");
    let executable = subcommand.artifact(
        artifact,
        if subcommand.target() == Some(subcommand.host_triple()) {
            None
        } else {
            subcommand.target()
        },
        cargo_subcommand::CrateType::Bin,
    );

    Ok(executable)
}

fn rootfs(root: &Path, metadata: &Metadata, executable: &Path) -> Result<()> {
    // Calculate root. If the root is not set in the cargo manifest create and use an empty tempdir.
    if let Some(metadata_root) = &metadata.root {
        copy_dir_all(root, metadata_root).context("failed to copy root")?;
    }

    // Extract init from the northstar manifest.
    let init: &Path = metadata
        .manifest
        .init
        .as_ref()
        .ok_or_else(|| anyhow!("resource containers are unsupported"))?
        .as_ref();
    let init_in_rootfs = root.join(init.strip_prefix("/").unwrap_or(init));

    // Check if init is a file in the rootfs provided.
    if init_in_rootfs.is_file() {
        bail!("failed create root fs. root contains {}", init.display());
    }
    // Check if init is a directory in the rootfs provided.
    if init_in_rootfs.is_dir() {
        bail!("failed create root fs. {} is a directoy", init.display());
    }

    // Create the parent dir of init in the tmp rootfs.
    if let Some(parent) = init_in_rootfs.parent() {
        debug_assert!(!parent.is_file());
        if !parent.is_dir() {
            fs::create_dir_all(parent).context("failed to create directory")?;
        }
    }

    fs::copy(executable, init_in_rootfs).context("failed to copy artifact")?;

    Ok(())
}

fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn stdout(choice: ColorChoice) -> StandardStream {
    let choice = match choice {
        ColorChoice::Always => termcolor::ColorChoice::Always,
        ColorChoice::Never => termcolor::ColorChoice::AlwaysAnsi,
        ColorChoice::Auto => {
            if atty::is(atty::Stream::Stdout) {
                termcolor::ColorChoice::Auto
            } else {
                termcolor::ColorChoice::Never
            }
        }
    };
    StandardStream::stdout(choice)
}
