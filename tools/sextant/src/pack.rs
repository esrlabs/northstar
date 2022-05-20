use anyhow::{Context, Result};
use northstar_runtime::npk::{
    manifest::Manifest,
    npk::{pack_with, SquashfsOptions},
};
use std::{convert::TryInto, fs, path::Path};
use tempfile::tempdir;

#[allow(clippy::too_many_arguments)]
pub(crate) fn pack(
    manifest: &Path,
    root: &Path,
    out: &Path,
    key: Option<&Path>,
    squashfs_options: SquashfsOptions,
    clones: Option<u32>,
) -> Result<()> {
    // Create npk clones with the number appended to the name
    if let Some(clones) = clones {
        let manifest_file = manifest;
        let reader = fs::File::open(&manifest_file).context("failed to open manifest")?;
        let mut manifest = Manifest::from_reader(reader).context("failed to read manifest")?;

        // Only clone non-resource containers
        if manifest.init.is_some() {
            let tmp = tempdir().context("failed to create temporary directory")?;
            let name = manifest.name.clone();
            let num = clones.to_string().chars().count();
            for n in 0..clones {
                manifest.name = format!("{}-{:0m$}", name, n, m = num)
                    .try_into()
                    .context("failed to parse name")?;
                let m = tmp.path().join(n.to_string());
                fs::write(&m, manifest.to_string()).context("failed to write manifest")?;
                pack_with(&m, root, out, key, squashfs_options.clone())?;
            }
        } else {
            pack_with(manifest_file, root, out, key, squashfs_options)?;
        }
    } else {
        pack_with(manifest, root, out, key, squashfs_options)?;
    }

    Ok(())
}
