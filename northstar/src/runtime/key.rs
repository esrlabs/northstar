use anyhow::{Context, Result};
use std::path::Path;
use tokio::fs;

pub type PublicKey = ed25519_dalek::PublicKey;

pub(super) async fn load(path: &Path) -> Result<PublicKey> {
    let key_bytes = fs::read(&path)
        .await
        .with_context(|| format!("failed to load key from {}", path.display()))?;
    PublicKey::from_bytes(&key_bytes).context("invalid key signature")
}
