// Copyright (c) 2020 ESRLabs
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

use ed25519_dalek::SignatureError;
use log::debug;
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
    debug!("Loading key {}", path.display());
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
