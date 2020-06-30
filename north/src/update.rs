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

use crate::{container, State, TerminationReason};
use anyhow::{Context, Result};
use async_std::{fs, path::Path};
use futures::stream::StreamExt;
use log::{debug, info};
use north_common::manifest::{Manifest, Version};
use std::{io::Read, str::FromStr, time};

const MANIFEST: &str = "manifest.yaml";

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

pub async fn update(state: &mut State, dir: &Path) -> Result<Vec<(String, (Version, Version))>> {
    let mut updates = Box::pin(
        fs::read_dir(&dir)
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
            }),
    );

    let mut result = vec![];

    while let Some(update) = updates.next().await {
        let file = std::fs::File::open(&update)
            .with_context(|| format!("Failed to open {}", update.display()))?;
        let reader = std::io::BufReader::new(file);
        let mut archive = zip::ZipArchive::new(reader).context("Failed to read zip")?;

        debug!("Loading manifest from {}", update.display());
        let manifest = {
            let mut manifest_file = archive
                .by_name(MANIFEST)
                .with_context(|| format!("Failed to read manifest from {}", update.display()))?;
            let mut manifest = String::new();
            manifest_file.read_to_string(&mut manifest)?;
            Manifest::from_str(&manifest)?
        };
        drop(archive);

        let old_version = manifest.version;
        let name = manifest.name;

        let is_installed = state.application(&name).is_some();
        let is_started = state
            .application(&name)
            .map(|a| a.process_context().map(|_| true).unwrap_or_default())
            .unwrap_or_default();

        if is_installed {
            if is_started {
                info!("Update: Stopping {}", name);
                state
                    .stop(
                        &name,
                        time::Duration::from_secs(10),
                        TerminationReason::Stopped,
                    )
                    .await?;
            }

            info!("Update: Uninstalling {}", name);
            state.uninstall(&name).await?;
        }

        info!("Update: Installing {}", update.display());
        let installed = container::install(state, &update).await?;
        let new_version: Version = installed.1;

        if is_started {
            state.start(&name, 0).await?;
        }

        result.push((name, (old_version, new_version)));
    }

    Ok(result)
}
