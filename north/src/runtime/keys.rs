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

use async_std::{fs, io, path::Path};
use ed25519_dalek::PublicKey;
use futures::{AsyncReadExt, StreamExt};
use log::info;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Io error: {context}")]
    Io {
        context: String,
        #[source]
        error: io::Error,
    },
    #[error("Invalid key signature: {0}")]
    Signature(String),
}

pub async fn load(key_dir: &Path) -> Result<HashMap<String, PublicKey>, Error> {
    let mut signing_keys = HashMap::new();
    let mut key_dir = fs::read_dir(&key_dir).await.map_err(|e| Error::Io {
        context: format!("Failed to open {}", key_dir.display()),
        error: e,
    })?;
    while let Some(entry) = key_dir.next().await {
        let entry = entry.map_err(|e| Error::Io {
            context: "Invalid key dir entry".to_string(),
            error: e,
        })?;
        // .context("Invalid key dir entry")?;
        let path = entry.path();
        if let Some(extension) = path.extension() {
            if extension == "pub" && path.is_file().await {
                if let Some(key_id) = path.file_stem().map(|s| s.to_string_lossy().to_string()) {
                    info!("Loading signing key {}", key_id);
                    let mut sign_key_file = fs::File::open(&path).await.map_err(|e| Error::Io {
                        context: format!("Failed to open {}", path.display()),
                        error: e,
                    })?;
                    let mut key_bytes = Vec::new();
                    sign_key_file
                        .read_to_end(&mut key_bytes)
                        .await
                        .map_err(|e| Error::Io {
                            context: format!("Failed to read {}", path.display()),
                            error: e,
                        })?;
                    let key = PublicKey::from_bytes(&key_bytes).map_err(|_| {
                        Error::Signature(format!("Signature error for key from {}", path.display()))
                    })?;
                    signing_keys.insert(key_id, key);
                }
            }
        }
    }
    Ok(signing_keys)
}
