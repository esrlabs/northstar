use ed25519_dalek::SignatureError;
use log::info;
use std::path::Path;
use thiserror::Error;
use tokio::{fs, io};

pub type PublicKey = ed25519_dalek::PublicKey;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid key file: {0}")]
    KeyFile(String),
    #[error("Invalid key signature: {0}")]
    Signature(#[from] SignatureError),
    #[error("IO error: {0}: {1:?}")]
    Io(String, io::Error),
}

pub(super) async fn load(path: &Path) -> Result<PublicKey, Error> {
    info!("Loading key {}", path.display());
    if path.extension().filter(|ext| *ext == "pub").is_none() || !path.is_file() {
        return Err(Error::KeyFile(format!(
            "{} not a file or has '.pub' extension",
            path.display()
        )));
    }

    let key_bytes = fs::read(&path)
        .await
        .map_err(|e| Error::Io(format!("Failed to load key from {}", path.display()), e))?;

    Ok(PublicKey::from_bytes(&key_bytes).map_err(Error::Signature)?)
}
