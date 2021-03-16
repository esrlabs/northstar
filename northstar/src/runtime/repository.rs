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
    ffi::OsStr,
    path::{Path, PathBuf},
};

use super::{
    error::Error,
    key::{self, PublicKey},
    Container, RepositoryId,
};
use futures::future::OptionFuture;
use log::debug;
use npk::npk::Npk;
use tokio::fs;

#[derive(Debug)]
pub(super) struct Repository {
    pub(super) id: RepositoryId,
    pub(super) dir: PathBuf,
    pub(super) key: Option<PublicKey>,
    pub(super) containers: HashMap<Container, PathBuf>,
    pub(super) npks: HashMap<Container, Npk>,
}

impl Repository {
    pub async fn new(
        id: RepositoryId,
        dir: PathBuf,
        key: Option<&Path>,
    ) -> Result<Repository, Error> {
        let key: OptionFuture<_> = key.map(|k| key::load(&k)).into();
        let mut containers = HashMap::new();
        let mut npks = HashMap::new();

        let mut readir = fs::read_dir(&dir)
            .await
            .map_err(|e| Error::Io("Repository read dir".into(), e))?;

        while let Ok(Some(entry)) = readir.next_entry().await {
            let npk_extension = Some(OsStr::new("npk"));
            if entry.path().extension() != npk_extension {
                continue;
            }

            let npk = Npk::from_path(entry.path().as_path(), None)
                .await
                .map_err(Error::Npk)?;
            let name = npk.manifest().name.clone();
            let version = npk.manifest().version.clone();
            let container = Container::new(name, version);
            containers.insert(container.clone(), entry.path());
            npks.insert(container, npk);
        }

        Ok(Repository {
            id,
            dir,
            key: key.await.transpose().map_err(Error::Key)?,
            containers,
            npks,
        })
    }

    pub async fn add(&mut self, container: &Container, src: &Path) -> Result<(), Error> {
        let dest = self
            .dir
            .join(format!("{}-{}.npk", container.name(), container.version()));

        // Check if the npk already in the repository
        if dest.exists() {
            return Err(Error::InstallDuplicate(container.clone()));
        }

        // Copy the npk to the repository
        fs::copy(src, &dest)
            .await
            .map_err(|e| Error::Io("Failed to copy npk to repository".into(), e))?;

        let npk = Npk::from_path(dest.as_path(), None)
            .await
            .map_err(Error::Npk)?;
        let name = npk.manifest().name.clone();
        let version = npk.manifest().version.clone();
        let container = Container::new(name, version);
        self.containers.insert(container.clone(), dest.to_owned());
        self.npks.insert(container, npk);

        Ok(())
    }

    pub async fn remove(&mut self, container: &Container) -> Result<(), Error> {
        if let Some(npk) = self.containers.remove(&container) {
            debug!("Removing {}", npk.display());
            self.npks.remove(&container);
            fs::remove_file(npk)
                .await
                .map_err(|e| Error::Io("Failed to remove npk".into(), e))
                .map(drop)
        } else {
            Err(Error::InvalidContainer(container.clone()))
        }
    }
}
