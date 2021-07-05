// Copyright (c) 2021 ESRLabs
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

use anyhow::{Context, Result};
use npk::{
    manifest::Manifest,
    npk::{pack_with, CompressionAlgorithm},
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
            let num = clones.to_string().chars().count() - 1;
            for n in 0..clones {
                manifest.name = format!("{}-{:0m$}", name, n, m = num)
                    .try_into()
                    .context("Failed to parse name")?;
                let m = tmp.path().join(n.to_string());
                fs::write(&m, manifest.to_string()).context("Failed to write manifest")?;
                pack_with(&m, &root, &out, key.as_deref(), &squashfs_opts)?;
            }
        } else {
            let key = key.as_deref();
            pack_with(&manifest_file, &root, &out, key, &squashfs_opts)?;
        }
    } else {
        pack_with(&manifest, &root, &out, key.as_deref(), &squashfs_opts)?;
    }

    Ok(())
}
