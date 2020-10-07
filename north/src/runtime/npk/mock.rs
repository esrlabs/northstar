// Copyright (c) 2019 - 2020 ESRLabs
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

use super::Container;
use crate::{
    manifest::{MountType, Name, Version},
    runtime::{error::InstallFailure, npk::ArchiveReader, state::State},
};
use anyhow::{Context, Result};
use async_std::{
    fs,
    os::unix,
    path::{Path, PathBuf},
};
use futures::stream::StreamExt;
use log::{debug, info};
use std::process::Command;

pub async fn install_all(state: &mut State, dir: &Path) -> Result<()> {
    info!("Installing containers from {}", dir.display());

    lazy_static::lazy_static! {
        static ref RE: regex::Regex = regex::Regex::new(
            format!(
                r"^.*-{}-\d+\.\d+\.\d+\.npk$",
                env!("VERGEN_TARGET_TRIPLE")
            )
            .as_str(),
        )
        .expect("Invalid regex");
    }

    let containers = fs::read_dir(&dir)
        .await
        .with_context(|| format!("Failed to read {}", dir.display()))?
        .filter_map(move |d| async move { d.ok() })
        .map(|d| d.path())
        .filter_map(move |d| async move {
            if RE.is_match(&d.display().to_string()) {
                Some(d)
            } else {
                None
            }
        });

    let mut containers = Box::pin(containers);
    while let Some(container) = containers.next().await {
        install(state, &container).await?;
    }
    Ok(())
}

pub async fn install(
    state: &mut State,
    npk: &Path,
) -> std::result::Result<(Name, Version), InstallFailure> {
    if let Some(npk_name) = npk.file_name() {
        info!("Loading {}", npk_name.to_string_lossy());
    }

    let (manifest, (fs_offset, _fs_size)) = {
        let mut archive_reader = ArchiveReader::new(npk.into(), &state.signing_keys)?;

        (
            archive_reader.extract_manifest_from_archive()?,
            archive_reader.extract_fs_start_and_size()?,
        )
    };

    if state.applications.contains_key(&manifest.name) {
        return Err(InstallFailure::ApplicationAlreadyInstalled(format!(
            "Cannot install container with name {} because it already exists",
            manifest.name
        )));
    }

    let instances = manifest.instances.unwrap_or(1);

    for instance in 0..instances {
        let mut manifest = manifest.clone();
        if instances > 1 {
            manifest.name.push_str(&format!("-{:03}", instance));
        }

        let run_dir: PathBuf = state.config.directories.run_dir.as_path().into();
        let root = run_dir.join(&manifest.name);

        if root.exists().await {
            debug!("Removing {}", root.display());
            fs::remove_dir_all(&root).await.map_err(|_| {
                InstallFailure::InternalError(format!("Failed to remove {}", root.display()))
            })?;
        }

        debug!("Unsquashing {} to {}", npk.display(), root.display());
        let mut cmd = Command::new("unsquashfs");
        cmd.arg("-o");
        cmd.arg(fs_offset.to_string());
        cmd.arg("-f");
        cmd.arg("-d");
        cmd.arg(root.display().to_string());
        cmd.arg(npk.display().to_string());
        let output = cmd
            .output()
            .map_err(|e| InstallFailure::InternalError(format!("Output error: {}", e)))?;
        if !output.status.success() {
            return Err(InstallFailure::InternalError(format!(
                "Failed to unsquash: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        for mount in manifest.mounts.iter() {
            match mount {
                Mount::Bind { target, host, .. } => {
                    let source = &host;
                    let target = root.join(target.strip_prefix("/")?);
                    // The mount points are part of the squashfs - remove them and symlink
                    if target.exists().await {
                        fs::remove_dir(&target)
                            .await
                            .with_context(|| format!("Failed to rmdir {}", target.display()))?;
                    }
                    unix::fs::symlink(source, &target).await.with_context(|| {
                        format!(
                            "Failed to link {} to {}",
                            source.display(),
                            target.display()
                        )
                    })?;
                }

                Mount::Persist { target, .. } => {
                    let dir = root.join(target.strip_prefix("/")?);
                    fs::create_dir_all(&dir)
                        .await
                        .with_context(|| format!("Failed to create {}", dir.display()))?;
                }

                _ => continue,
            }
        }

        info!("Installed {}:{}", manifest.name, manifest.version);

        let container = Container { root, manifest };

        state.add(container)?;
    }

    Ok((manifest.name, manifest.version))
}

pub async fn uninstall(container: &Container) -> Result<()> {
    debug!("Removing {}", container.root.display());
    fs::remove_dir_all(&container.root)
        .await
        .with_context(|| format!("Failed to remove {}", container.root.display()))
}
