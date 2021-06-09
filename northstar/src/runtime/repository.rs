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

use super::{
    error::Error,
    key::{self, PublicKey},
    Container, RepositoryId,
};
use floating_duration::TimeAsFloat;
use futures::future::OptionFuture;
use log::{debug, info};
use npk::npk::Npk;
use std::{
    collections::HashMap,
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{fs, task, time::Instant};

#[derive(Debug)]
pub(super) struct Repository {
    pub(super) id: RepositoryId,
    pub(super) dir: PathBuf,
    pub(super) key: Option<PublicKey>,
    pub(super) containers: HashMap<Container, (PathBuf, Arc<Npk>)>,
}

impl Repository {
    pub async fn new(
        id: RepositoryId,
        dir: PathBuf,
        key: Option<&Path>,
    ) -> Result<Repository, Error> {
        let mut containers = HashMap::new();

        info!("Loading repository {}", dir.display());

        let key: OptionFuture<_> = key.map(key::load).into();
        let key = key.await.transpose().map_err(Error::Key)?;

        let mut readir = fs::read_dir(&dir)
            .await
            .map_err(|e| Error::Io("Repository read dir".into(), e))?;

        let start = Instant::now();
        while let Ok(Some(entry)) = readir.next_entry().await {
            let npk_extension = Some(OsStr::new("npk"));
            if entry.path().extension() != npk_extension {
                continue;
            }

            debug!("Loading {}", entry.path().display());
            let npk = task::block_in_place(|| Npk::from_path(entry.path().as_path(), key.as_ref()))
                .map_err(|e| Error::Npk(entry.path(), e))?;
            let name = npk.manifest().name.clone();
            let version = npk.manifest().version.clone();
            let container = Container::new(name, version);
            containers.insert(container.clone(), (entry.path(), Arc::new(npk)));
        }
        let duration = start.elapsed();
        info!(
            "Loaded {} containers from {} in {:.03}s (avg: {:.03}s)",
            containers.len(),
            dir.display(),
            duration.as_fractional_secs(),
            duration.as_fractional_secs() / containers.len() as f64
        );

        Ok(Repository {
            id,
            dir,
            key,
            containers,
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

        debug!("Loading {}", dest.display());
        let npk = task::block_in_place(|| Npk::from_path(dest.as_path(), self.key.as_ref()))
            .map_err(|e| Error::Npk(dest.clone(), e))?;
        let name = npk.manifest().name.clone();
        let version = npk.manifest().version.clone();
        let container = Container::new(name, version);
        self.containers
            .insert(container, (dest.to_owned(), Arc::new(npk)));

        Ok(())
    }

    pub async fn remove(&mut self, container: &Container) -> Result<(), Error> {
        if let Some((npk, _)) = self.containers.remove(&container) {
            debug!("Removing {}", npk.display());
            fs::remove_file(npk)
                .await
                .map_err(|e| Error::Io("Failed to remove npk".into(), e))
                .map(drop)
        } else {
            Err(Error::InvalidContainer(container.clone()))
        }
    }
}
