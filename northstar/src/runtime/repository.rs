// Copyright (c) 2021 ESRLabs
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

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::SystemTime,
};

use super::{error::Error, Container, Name, RepositoryId, Version};
use ed25519_dalek::PublicKey;
use log::debug;
use npk::npk::Npk;
use tokio::fs;

#[derive(Debug, Clone)]
pub(super) struct Repository {
    pub(super) id: RepositoryId,
    pub(super) dir: PathBuf,
    pub(super) key: Option<PublicKey>,
    last_modified: Option<SystemTime>,
    containers: HashMap<(Name, Version), PathBuf>,
}

impl Repository {
    pub async fn new(
        id: RepositoryId,
        dir: PathBuf,
        key: Option<PublicKey>,
    ) -> Result<Repository, Error> {
        let mut repository = Repository {
            id,
            dir,
            key,
            last_modified: None,
            containers: HashMap::new(),
        };
        repository.scan().await?;
        Ok(repository)
    }

    pub fn npks(&self) -> &HashMap<(Name, Version), PathBuf> {
        &self.containers
    }

    pub async fn add(&mut self, container: &Container, src: &Path) -> Result<(), Error> {
        let dest = self
            .dir
            .join(format!("{}-{}.npk", container.name(), container.version()));

        // Check if the npk already in the repository
        if dest.exists() {
            return Err(Error::ApplicationInstalled(container.clone()));
        }

        // Copy the npk to the repository
        fs::copy(src, &dest)
            .await
            .map_err(|e| Error::Io("Failed to copy npk to repository".into(), e))?;

        self.containers.insert(
            (container.name().clone(), container.version().clone()),
            dest,
        );

        self.last_modified = Some(
            fs::metadata(&self.dir)
                .await
                .map_err(|e| Error::Io("Repository metadata".into(), e))?
                .modified()
                .map_err(|e| Error::Io("Repository modified".into(), e))?,
        );

        Ok(())
    }

    pub async fn remove(&mut self, container: &Container) -> Result<(), Error> {
        let npk = self
            .dir
            .join(format!("{}-{}.npk", container.name(), container.version()));
        debug!("Removing {}", npk.display());
        fs::remove_file(npk)
            .await
            .map_err(|e| Error::Io("Failed to remove npk".into(), e))?;
        self.containers
            .remove(&(container.name().clone(), container.version().clone()));

        self.last_modified = Some(
            fs::metadata(&self.dir)
                .await
                .map_err(|e| Error::Io("Repository metadata".into(), e))?
                .modified()
                .map_err(|e| Error::Io("Repository modified".into(), e))?,
        );
        Ok(())
    }

    async fn scan(&mut self) -> Result<(), Error> {
        let last_modified = fs::metadata(&self.dir)
            .await
            .map_err(|e| Error::Io("Repository metadata".into(), e))?
            .modified()
            .map_err(|e| Error::Io("Repository modified".into(), e))?;

        if self.last_modified.is_none() || self.last_modified.unwrap() != last_modified {
            self.containers.clear();
            let mut readir = fs::read_dir(&self.dir)
                .await
                .map_err(|e| Error::Io("Repository read dir".into(), e))?;
            while let Ok(Some(entry)) = readir.next_entry().await {
                // TODO: Replace with file name regex etc...
                let npk = fs::File::open(entry.path())
                    .await
                    .map_err(|e| Error::Io("Failed to read npk".into(), e))?;
                let npk = Npk::new(npk, None).await.map_err(Error::Npk)?;
                let name = npk.manifest().name.clone();
                let version = npk.manifest().version.clone();
                self.containers.insert((name, version), entry.path());
            }
            self.last_modified = Some(last_modified);
        }
        Ok(())
    }
}
