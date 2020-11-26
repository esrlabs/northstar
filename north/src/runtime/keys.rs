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

use ed25519_dalek::*;
use log::info;
use std::{collections::HashMap, path::Path};
use thiserror::Error;
use tokio::{fs, io, stream::StreamExt};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid key signature: {0}")]
    Signature(#[from] SignatureError),
    #[error("IO error: {0}: {1:?}")]
    Io(String, io::Error),
}

pub(super) async fn load(key_dir: &Path) -> Result<HashMap<String, PublicKey>, Error> {
    let mut signing_keys = HashMap::new();
    let mut key_dir = fs::read_dir(&key_dir).await.map_err(|e| {
        Error::Io(
            format!("Failed to load keys from: {}", key_dir.display()),
            e,
        )
    })?;
    while let Some(entry) = key_dir.next().await {
        let path = entry
            .map_err(|e| Error::Io("Failed to read dir entry".to_string(), e))?
            .path();
        if path.extension().filter(|ext| *ext == "pub").is_none() || !path.is_file() {
            continue;
        }

        if let Some(key_id) = path.file_stem().map(|s| s.to_string_lossy().to_string()) {
            info!("Loading signing key {}", key_id);
            let key_bytes = fs::read(&path)
                .await
                .map_err(|e| Error::Io(format!("Failed to load key from {}", path.display()), e))?;
            let key = PublicKey::from_bytes(&key_bytes).map_err(Error::Signature)?;
            signing_keys.insert(key_id, key);
        }
    }
    Ok(signing_keys)
}
