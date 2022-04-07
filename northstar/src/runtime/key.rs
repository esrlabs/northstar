use ed25519_dalek::SignatureError;
use std::path::Path;
use thiserror::Error;
use tokio::{fs, io};

pub type PublicKey = ed25519_dalek::PublicKey;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid key file: {0}")]
    KeyFile(String),
    #[error("invalid key signature: {0}")]
    Signature(#[from] SignatureError),
    #[error("io error: {0}: {1:?}")]
    Io(String, io::Error),
}

pub(super) async fn load(path: &Path) -> Result<PublicKey, Error> {
    let key_bytes = fs::read(&path)
        .await
        .map_err(|e| Error::Io(format!("failed to load key from {}", path.display()), e))?;

    PublicKey::from_bytes(&key_bytes).map_err(Error::Signature)
}
