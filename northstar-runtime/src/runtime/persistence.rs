use std::{fs::Permissions, os::unix::prelude::PermissionsExt};

use crate::npk::manifest::{mount::Mount, Manifest};
use anyhow::{Context, Result};
use log::debug;
use nix::unistd;
use tokio::fs;

use super::config;

/// Permissions for the persist directory.
const PERSIST_DIR_PERMISSIONS: u32 = 0o700;

/// Create all persistence directories for the given manifest and setup permissions and ownership.
pub(crate) async fn setup(config: &config::Config, manifest: &Manifest) -> Result<()> {
    if manifest
        .mounts
        .iter()
        .any(|(_, mount)| matches!(mount, Mount::Persist))
    {
        // The directory is the data directory + the container name. The version is not included
        // because the persist directory is shared between versions.
        let dir = config.data_dir.join(manifest.name.as_ref());

        // mkdir
        if !dir.exists() {
            debug!("Creating {}", dir.display());
            fs::create_dir_all(&dir)
                .await
                .with_context(|| format!("failed to create directory {}", dir.display()))?;
        }

        // chmod
        debug!(
            "Setting directory mode {} on {}",
            umask::Mode::from(PERSIST_DIR_PERMISSIONS),
            dir.display(),
        );
        fs::set_permissions(&dir, Permissions::from_mode(PERSIST_DIR_PERMISSIONS))
            .await
            .with_context(|| format!("failed to set permission on {}", dir.display()))?;

        // chown
        let uid = unistd::Uid::from_raw(manifest.uid.into());
        let gid = unistd::Gid::from_raw(manifest.gid.into());
        debug!("Chowning {} to {uid}:{gid}", dir.display());
        unistd::chown(dir.as_os_str(), Some(uid), Some(gid)).context(format!(
            "failed to chown {} to {}:{}",
            dir.display(),
            uid,
            gid
        ))?;
    }

    Ok(())
}
