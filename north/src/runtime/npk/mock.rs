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
    manifest::{Mount, Name, Version},
    runtime::{error::InstallationError, npk::ArchiveReader, state::State},
};
use log::{debug, info};
use std::{io, path::Path, process::Command};
use tokio::{
    fs::{self, os::unix::symlink},
    stream::StreamExt,
};

pub async fn mount_all(state: &mut State, dir: &Path) -> Result<(), InstallationError> {
    info!("Mounting containers from {}", dir.display());

    let npks = fs::read_dir(&dir)
        .await
        .map_err(|e| InstallationError::Io {
            context: format!("Failed to read {}", dir.display()),
            error: e,
        })?
        .filter_map(move |d| d.ok())
        .map(|d| d.path());

    let mut npks = Box::pin(npks);
    while let Some(npk) = npks.next().await {
        mount(state, &npk).await?;
    }
    Ok(())
}

pub async fn mount(state: &mut State, npk: &Path) -> Result<(Name, Version), InstallationError> {
    if let Some(npk_name) = npk.file_name() {
        info!("Loading {}", npk_name.to_string_lossy());
    }

    let (manifest, (fs_offset, _fs_size)) = {
        let mut archive_reader = ArchiveReader::new(npk, &state.signing_keys)?;
        (
            archive_reader.extract_manifest_from_archive()?,
            archive_reader.extract_fs_start_and_size()?,
        )
    };

    if state.applications.contains_key(&manifest.name) {
        return Err(InstallationError::ApplicationAlreadyInstalled(format!(
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

        let run_dir = state.config.directories.run_dir.as_path();
        let root = run_dir.join(&manifest.name);

        if root.exists() {
            debug!("Removing {}", root.display());
            fs::remove_dir_all(&root)
                .await
                .map_err(|e| InstallationError::Io {
                    context: format!("Failed to remove {}", root.display()),
                    error: e,
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
        let output = cmd.output().map_err(|e| InstallationError::Io {
            context: format!("Output error: {}", e),
            error: e,
        })?;
        if !output.status.success() {
            return Err(InstallationError::Io {
                context: format!(
                    "Failed to unsquash: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
                error: io::Error::new(io::ErrorKind::Other, "unsquash failed"),
            });
        }

        for mount in manifest.mounts.iter() {
            match mount {
                Mount::Bind { target, host, .. } => {
                    let source = &host;
                    let target =
                        root.join(
                            target
                                .strip_prefix("/")
                                .map_err(|_| InstallationError::Io {
                                    context: "join error".to_string(),
                                    error: io::Error::new(io::ErrorKind::Other, "join error"),
                                })?,
                        );
                    // The mount points are part of the squashfs - remove them and symlink
                    if target.exists() {
                        fs::remove_dir(&target)
                            .await
                            .map_err(|e| InstallationError::Io {
                                context: format!("Failed to rmdir {}", target.display()),
                                error: e,
                            })?;
                    }
                    symlink(source, &target)
                        .await
                        .map_err(|e| InstallationError::Io {
                            context: format!(
                                "Failed to link {} to {}",
                                source.display(),
                                target.display()
                            ),
                            error: e,
                        })?;
                }

                Mount::Persist { target, .. } => {
                    let dir =
                        root.join(
                            target
                                .strip_prefix("/")
                                .map_err(|_| InstallationError::Io {
                                    context: "Failed to join".to_string(),
                                    error: io::Error::new(io::ErrorKind::Other, "join error"),
                                })?,
                        );
                    fs::create_dir_all(&dir)
                        .await
                        .map_err(|e| InstallationError::Io {
                            context: format!("Failed to create {}", dir.display()),
                            error: e,
                        })?;
                }

                _ => continue,
            }
        }

        info!("Mounted {}:{}", manifest.name, manifest.version);

        let container = Container { root, manifest };

        state.add(container)?;
    }

    Ok((manifest.name, manifest.version))
}

pub async fn umount(container: &Container) -> Result<(), InstallationError> {
    debug!("Removing {}", container.root.display());
    fs::remove_dir_all(&container.root)
        .await
        .map_err(|e| InstallationError::Io {
            context: format!("Failed to remove {}", container.root.display()),
            error: e,
        })
}
