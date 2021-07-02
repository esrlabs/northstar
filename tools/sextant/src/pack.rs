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
    oci::{convert_oci_spec_to_manifest, load_oci_spec},
};
use std::{fs, path::Path};

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

    // Tries to check if the input manifest is an OCI spec
    let manifest = if let Ok(oci_spec) = load_oci_spec(&manifest) {
        convert_oci_spec_to_manifest(oci_spec)?
    } else {
        let manifest_file = manifest;
        let reader = fs::File::open(&manifest_file).context("Failed to open manifest")?;
        Manifest::from_reader(reader).context("Failed to read manifest")?
    };

    // Create clones npks with the number appended to the name
    if let Some(clones) = clones {
        // Resource containers cannot be cloned
        if manifest.init.is_some() {
            let name = manifest.name.clone();
            let num = clones.to_string().chars().count() - 1;
            for n in 0..clones {
                let mut manifest = manifest.clone();
                manifest.name = format!("{}-{:0m$}", name, n, m = num);
                pack_with(manifest, &root, &out, key.as_deref(), &squashfs_opts)?;
            }
        } else {
            let key = key.as_deref();
            pack_with(manifest, &root, &out, key, &squashfs_opts)?;
        }
    } else {
        pack_with(manifest, &root, &out, key.as_deref(), &squashfs_opts)?;
    }

    Ok(())
}
