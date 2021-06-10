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
    state::Npk,
    Container, RepositoryId,
};
use floating_duration::TimeAsFloat;
use futures::{
    future::{join_all, ready, OptionFuture},
    FutureExt,
};
use log::{debug, info, warn};
use npk::npk;
use std::{
    collections::HashMap,
    ffi::{CStr, OsStr},
    fmt,
    io::{BufReader, Seek, SeekFrom, Write},
    os::unix::prelude::{FromRawFd, RawFd},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{fs, io, task, time::Instant};

#[async_trait::async_trait]
pub(super) trait Repository: fmt::Debug {
    /// Add npk from `src` to repositoriy. Open the npk and parse content
    async fn add(&mut self, src: &Path) -> Result<Container, Error>;

    /// Add container from repository if present
    async fn remove(&mut self, container: &Container) -> Result<(), Error>;

    /// Return npk matching container if present
    fn get(&self, container: &Container) -> Option<Arc<Npk>>;

    /// Key of this repository
    fn key(&self) -> Option<&PublicKey> {
        None
    }
    /// All containers in this repositoriy
    fn containers(&self) -> Vec<Arc<Npk>>;
}

/// Repository backed by a directory
#[derive(Debug)]
pub(super) struct DirRepository {
    id: RepositoryId,
    dir: PathBuf,
    key: Option<PublicKey>,
    containers: HashMap<Container, (PathBuf, Arc<Npk>)>,
}

impl DirRepository {
    pub async fn new(
        id: RepositoryId,
        dir: PathBuf,
        key: Option<&Path>,
    ) -> Result<DirRepository, Error> {
        let mut containers = HashMap::new();

        info!("Loading repository {}", dir.display());

        let key: OptionFuture<_> = key.map(key::load).into();
        let key = key.await.transpose().map_err(Error::Key)?;

        let mut readir = fs::read_dir(&dir)
            .await
            .map_err(|e| Error::Io("Repository read dir".into(), e))?;

        let start = Instant::now();
        let mut loads = vec![];
        let npk_extension = Some(OsStr::new("npk"));
        while let Ok(Some(entry)) = readir.next_entry().await {
            let file = entry.path();
            if file.extension() == npk_extension {
                let task = task::spawn_blocking(move || {
                    debug!(
                        "Loading {}{}",
                        file.display(),
                        if key.is_some() { " [verified]" } else { "" }
                    );
                    let npk = Npk::from_path(&file, key.as_ref())
                        .map_err(|e| Error::Npk(file.display().to_string(), e))?;
                    let name = npk.manifest().name.clone();
                    let version = npk.manifest().version.clone();
                    let container = Container::new(name, version);
                    Result::<_, Error>::Ok((container, file, npk))
                })
                .then(|r| match r {
                    Ok(r) => ready(r),
                    Err(_) => panic!("Task error"),
                });
                loads.push(task);
            } else {
                debug!("Skipping {}", file.display());
            }
        }

        let results = join_all(loads).await;
        for result in results {
            match result {
                Ok((container, file, npk)) => {
                    containers.insert(container, (file, Arc::new(npk)));
                }
                Err(e) => warn!("Failed to load: {}", e),
            }
        }

        let duration = start.elapsed();
        info!(
            "Loaded {} containers from {} in {:.03}s (avg: {:.05}s)",
            containers.len(),
            dir.display(),
            duration.as_fractional_secs(),
            duration.as_fractional_secs() / containers.len() as f64
        );

        Ok(DirRepository {
            id,
            dir,
            key,
            containers,
        })
    }
}

#[async_trait::async_trait]
impl<'a> Repository for DirRepository {
    async fn add(&mut self, src: &Path) -> Result<Container, Error>
    where
        Self: Sized,
    {
        let dest = self.dir.join(format!("{}.npk", uuid::Uuid::new_v4()));
        // Copy the npk to the repository
        fs::copy(src, &dest)
            .await
            .map_err(|e| Error::Io("Failed to copy npk to repository".into(), e))?;

        debug!("Loading {}", dest.display());
        let npk = match task::block_in_place(|| Npk::from_path(dest.as_path(), self.key.as_ref()))
            .map_err(|e| Error::Npk(dest.display().to_string(), e))
        {
            Ok(n) => Ok(n),
            Err(e) => {
                fs::remove_file(&dest)
                    .await
                    .map_err(|e| Error::io("Remove file from repository", e))?;
                Err(e)
            }
        }?;
        let name = npk.manifest().name.clone();
        let version = npk.manifest().version.clone();
        let container = Container::new(name, version);
        if self.containers.contains_key(&container) {
            fs::remove_file(&dest)
                .await
                .map_err(|e| Error::io("Remove file from repository", e))?;
            return Err(Error::InstallDuplicate(container.clone()));
        }
        self.containers
            .insert(container.clone(), (dest.to_owned(), Arc::new(npk)));
        debug!("Loaded {}", container);

        Ok(container)
    }

    async fn remove(&mut self, container: &Container) -> Result<(), Error>
    where
        Self: Sized,
    {
        if let Some((path, npk)) = self.containers.remove(&container) {
            debug!("Removing {} from {}", path.display(), self.id);
            drop(npk);
            fs::remove_file(path)
                .await
                .map_err(|e| Error::io("Failed to remove npk", e))
                .map(drop)
        } else {
            Ok(())
        }
    }

    fn get(&self, container: &Container) -> Option<Arc<Npk>>
    where
        Self: Sized,
    {
        self.containers.get(container).map(|(_, npk)| npk.clone())
    }

    fn key(&self) -> Option<&PublicKey>
    where
        Self: Sized,
    {
        self.key.as_ref()
    }

    fn containers(&self) -> Vec<Arc<Npk>>
    where
        Self: Sized,
    {
        self.containers
            .values()
            .map(|(_, npk)| npk.clone())
            .collect()
    }
}

/// In memory repository
#[derive(Default, Debug)]
pub(super) struct MemRepository {
    id: RepositoryId,
    containers: HashMap<Container, (Vec<u8>, Arc<Npk>)>,
}

impl MemRepository {
    pub(super) async fn add_buf(&mut self, buf: &[u8]) -> Result<Container, Error> {
        let data = Vec::from(buf);
        let fd = Self::memfd_create().map_err(|e| Error::Os("Failed create memfd".into(), e))?;
        let file = task::block_in_place(|| {
            let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
            file.write_all(buf)
                .map_err(|e| Error::io("Failed copy npk", e))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|e| Error::io("Failed seek", e))?;
            Result::<_, Error>::Ok(BufReader::new(file))
        })?;
        let npk = npk::Npk::from_reader(file, None).map_err(|e| Error::Npk("Memory".into(), e))?;
        let manifest = npk.manifest();
        let container = Container::new(manifest.name.clone(), manifest.version.clone());

        self.containers
            .insert(container.clone(), (data, Arc::new(npk)));

        Ok(container)
    }

    #[cfg(target_os = "android")]
    fn memfd_create() -> nix::Result<RawFd> {
        let name = CStr::from_bytes_with_nul(b"foo\0").unwrap();
        let res = unsafe { nix::libc::syscall(nix::libc::SYS_memfd_create, name.as_ptr(), 0) };
        nix::errno::Errno::result(res).map(|r| r as RawFd)
    }

    #[cfg(not(target_os = "android"))]
    pub fn memfd_create() -> nix::Result<RawFd> {
        let name = CStr::from_bytes_with_nul(b"foo\0").unwrap();
        nix::sys::memfd::memfd_create(&name, nix::sys::memfd::MemFdCreateFlag::empty())
    }
}

#[async_trait::async_trait]
impl<'a> Repository for MemRepository {
    async fn add(&mut self, file: &Path) -> Result<Container, Error>
    where
        Self: Sized,
    {
        let mut file = fs::File::open(&file)
            .await
            .map_err(|e| Error::io("Failed open npk", e))?;
        let mut data = Vec::new();
        io::copy(&mut file, &mut data)
            .await
            .map_err(|e| Error::io("Failed copy npk", e))?;
        self.add_buf(&data).await
    }

    async fn remove(&mut self, container: &Container) -> Result<(), Error>
    where
        Self: Sized,
    {
        self.containers.remove(container);
        Ok(())
    }

    fn get(&self, container: &Container) -> Option<Arc<Npk>>
    where
        Self: Sized,
    {
        self.containers.get(container).map(|(_, npk)| npk.clone())
    }

    fn containers(&self) -> Vec<Arc<Npk>>
    where
        Self: Sized,
    {
        self.containers
            .values()
            .map(|(_, npk)| npk.clone())
            .collect()
    }
}
