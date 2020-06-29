// Copyright (c) 2020 E.S.R.Labs. All rights reserved.
//
// NOTICE:  All information contained herein is, and remains
// the property of E.S.R.Labs and its suppliers, if any.
// The intellectual and technical concepts contained herein are
// proprietary to E.S.R.Labs and its suppliers and may be covered
// by German and Foreign Patents, patents in process, and are protected
// by trade secret or copyright law.
// Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained
// from E.S.R.Labs.

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
