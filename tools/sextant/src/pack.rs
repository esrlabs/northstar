use anyhow::{Context, Result};
use northstar::{
    npk,
    npk::{
        manifest::Manifest,
        npk::{pack_with, CompressionAlgorithm},
    },
};
use std::{convert::TryInto, fs, path::Path};
use tempfile::tempdir;

pub(crate) fn pack(
    manifest: &Path,
    root: &Path,
    out: &Path,
    key: Option<&Path>,
    comp: CompressionAlgorithm,
    block_size: Option<u32>,
    clones: Option<u32>,
) -> Result<()> {
    let squashfs_opts = npk::npk::SquashfsOpts { comp, block_size };
    // Create npk clones with the number appended to the name
    if let Some(clones) = clones {
        let manifest_file = manifest;
        let reader = fs::File::open(&manifest_file).context("Failed to open manifest")?;
        let mut manifest = Manifest::from_reader(reader).context("Failed to read manifest")?;

        // Only clone non-resource containers
        if manifest.init.is_some() {
            let tmp = tempdir().context("Failed to create temporary directory")?;
            let name = manifest.name.clone();
            let num = clones.to_string().chars().count();
            for n in 0..clones {
                manifest.name = format!("{}-{:0m$}", name, n, m = num)
                    .try_into()
                    .context("Failed to parse name")?;
                let m = tmp.path().join(n.to_string());
                fs::write(&m, manifest.to_string()).context("Failed to write manifest")?;
                pack_with(&m, root, out, key, &squashfs_opts)?;
            }
        } else {
            pack_with(manifest_file, root, out, key, &squashfs_opts)?;
        }
    } else {
        pack_with(manifest, root, out, key, &squashfs_opts)?;
    }

    Ok(())
}
