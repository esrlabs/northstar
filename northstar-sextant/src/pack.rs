use anyhow::{Context, Result};
use northstar_runtime::npk::{
    manifest::Manifest,
    npk::{pack_with_manifest, SquashfsOptions},
};
use std::{convert::TryInto, fs, path::Path};

#[allow(clippy::too_many_arguments)]
pub(crate) fn pack(
    manifest: &Path,
    root: &Path,
    out: &Path,
    key: Option<&Path>,
    squashfs_options: SquashfsOptions,
    clones: Option<u32>,
) -> Result<()> {
    let reader = fs::File::open(manifest).context("failed to open manifest")?;
    let mut manifest = Manifest::from_reader(reader).context("failed to read manifest")?;

    // Create npk clones with the number appended to the name
    if let Some(clones) = clones {
        // Only clone non-resource containers
        if manifest.init.is_some() {
            let name = manifest.name.clone();
            let num = clones.to_string().chars().count();
            for n in 0..clones {
                manifest.name = format!("{name}-{n:0num$}")
                    .try_into()
                    .context("failed to parse name")?;
                pack_with_manifest(&manifest, root, out, key, Some(&squashfs_options))?;
            }
        } else {
            pack_with_manifest(&manifest, root, out, key, Some(&squashfs_options))?;
        }
    } else {
        pack_with_manifest(&manifest, root, out, key, Some(&squashfs_options))?;
    }

    Ok(())
}
