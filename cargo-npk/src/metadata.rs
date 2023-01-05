use anyhow::{anyhow, Context};
use northstar_runtime::npk::manifest::Manifest;
use std::{collections::HashMap, fs};

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Deserializer};

#[derive(Debug)]
pub struct Metadata {
    pub manifest: Manifest,
    pub use_cross: bool,
    pub root: Option<PathBuf>,
}

impl Metadata {
    pub fn deserilize<'de, D>(cargo_manifest: &Path, deserializer: D, target: &str) -> Result<Self>
    where
        D: Deserializer<'de>,
        <D as Deserializer<'de>>::Error: Send + Sync + 'static,
    {
        /// Either a path to a northstar manifest or a manifest itself.
        #[derive(Clone, Debug, Deserialize)]
        #[serde(untagged)]
        enum NpkManifest {
            Path(PathBuf),
            Manifest(Box<Manifest>),
        }

        /// Cargo manifest metadata wrapper.
        #[derive(Clone, Debug, Default, Deserialize)]
        struct PackageMetadata {
            npk: Option<NpkMetadata>,
        }

        #[derive(Clone, Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct NpkMetadata {
            /// A northstar manfiest.
            manifest: Option<NpkManifest>,
            /// Root tree.
            root: Option<PathBuf>,
            /// Target specific settings have precedence over
            /// global ones defined on this level.
            #[serde(default)]
            target: HashMap<String, NpkTarget>,
        }

        #[derive(Clone, Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct NpkTarget {
            manifest: Option<NpkManifest>,
            /// Root tree.
            root: Option<PathBuf>,
            /// Use cross for building.
            #[serde(default)]
            use_cross: bool,
        }

        let mut metadata = PackageMetadata::deserialize(deserializer)?;
        let mut npk = metadata
            .npk
            .take()
            .ok_or_else(|| anyhow!("missing npk section in manifest"))?;

        // Try to get target specific settings.
        let (manifest, root, use_cross) = if let Some(target) = npk.target.remove(target) {
            (target.manifest, target.root, target.use_cross)
        } else {
            (None, None, false)
        };

        let root = root.or(npk.root);
        let manifest = match manifest
            .or(npk.manifest)
            .ok_or_else(|| anyhow!("failed to find manifest"))?
        {
            NpkManifest::Path(path) => {
                let path = if path.is_absolute() {
                    path
                } else if let Some(parent) = cargo_manifest.parent() {
                    parent.join(path)
                } else {
                    path
                };

                let reader = fs::File::open(path)?;
                Manifest::from_reader(reader).context("failed to parse manifest")?
            }
            NpkManifest::Manifest(manifest) => *manifest,
        };

        Ok(Self {
            manifest,
            use_cross,
            root,
        })
    }
}
