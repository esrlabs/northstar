use super::{
    error::Error,
    key::{self, PublicKey},
    state::Npk,
    Container, RepositoryId,
};
use crate::{npk::npk, runtime::pipe::RawFdExt};
use bytes::Bytes;
use floating_duration::TimeAsFloat;
use futures::{
    future::{join_all, ready, OptionFuture},
    FutureExt,
};
use log::{debug, info, warn};
use mpsc::Receiver;
use std::{
    collections::{HashMap, HashSet},
    fmt,
    io::{BufReader, ErrorKind, SeekFrom},
    os::unix::prelude::{AsRawFd, FromRawFd, IntoRawFd},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    fs,
    io::{self, AsyncSeekExt, AsyncWriteExt},
    sync::mpsc,
    task,
    time::Instant,
};

#[async_trait::async_trait]
pub(super) trait Repository: fmt::Debug {
    /// Stream an npk from `rx` into the repository and load it
    async fn insert(&mut self, rx: &mut Receiver<Bytes>) -> Result<Container, Error>;

    /// Add container from repository if present
    async fn remove(&mut self, container: &Container) -> Result<(), Error>;

    /// Return npk matching container if present
    fn get(&self, container: &Container) -> Option<Arc<Npk>>;

    /// Key of this repository
    fn key(&self) -> Option<&PublicKey>;

    /// All containers in this repositoriy
    fn containers(&self) -> Vec<Arc<Npk>>;

    /// List of all containers
    fn list(&self) -> Vec<Container>;
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
        dir: &Path,
        key: Option<&Path>,
        blacklist: &HashSet<Container>,
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
        let blacklist = Arc::new(blacklist.clone());
        while let Ok(Some(entry)) = readir.next_entry().await {
            let file = entry.path();
            let blacklist = blacklist.clone();
            let task = task::spawn(async move {
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

                if blacklist.contains(&container) {
                    Err(Error::DuplicateContainer(container))
                } else {
                    Ok((container, file, npk))
                }
            })
            .then(|r| match r {
                Ok(r) => ready(r),
                Err(_) => panic!("Task error"),
            });
            loads.push(task);
        }

        let results = join_all(loads).await;
        for result in results {
            match result {
                Ok((container, file, npk)) => {
                    // If the container name/version is already in there remove the present
                    // container and skip the newly parsed one.
                    if containers.remove(&container).is_some() {
                        warn!("Skipping duplicate container {}", container);
                    } else {
                        containers.insert(container, (file, Arc::new(npk)));
                    }
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
            dir: dir.to_owned(),
            key,
            containers,
        })
    }
}

#[async_trait::async_trait]
impl<'a> Repository for DirRepository {
    async fn insert(&mut self, rx: &mut Receiver<Bytes>) -> Result<Container, Error> {
        let dest = self.dir.join(format!("{}.npk", uuid::Uuid::new_v4()));
        let mut file = fs::File::create(&dest)
            .await
            .map_err(|e| Error::Io("Failed create npk in repository".into(), e))?;
        while let Some(r) = rx.recv().await {
            file.write_all(&r)
                .await
                .map_err(|e| Error::Io("Failed to write npk".into(), e))?;
        }
        file.flush()
            .await
            .map_err(|e| Error::Io("Failed to flush npk".into(), e))?;
        drop(file);

        debug!("Loading {}", dest.display());
        let npk = match Npk::from_path(dest.as_path(), self.key.as_ref())
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
            Err(Error::InstallDuplicate(container.clone()))
        } else {
            self.containers
                .insert(container.clone(), (dest.to_owned(), Arc::new(npk)));
            info!("Loaded {} into {}", container, self.id);
            Ok(container)
        }
    }

    async fn remove(&mut self, container: &Container) -> Result<(), Error> {
        if let Some((path, npk)) = self.containers.remove(container) {
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

    fn get(&self, container: &Container) -> Option<Arc<Npk>> {
        self.containers.get(container).map(|(_, npk)| npk.clone())
    }

    fn key(&self) -> Option<&PublicKey> {
        self.key.as_ref()
    }

    fn containers(&self) -> Vec<Arc<Npk>> {
        self.containers
            .values()
            .map(|(_, npk)| npk.clone())
            .collect()
    }

    fn list(&self) -> Vec<Container> {
        self.containers.keys().cloned().collect()
    }
}

/// In memory repository
#[derive(Debug)]
pub(super) struct MemRepository {
    id: RepositoryId,
    key: Option<PublicKey>,
    containers: HashMap<Container, Arc<Npk>>,
}

impl MemRepository {
    pub async fn new(id: RepositoryId, key: Option<&Path>) -> Result<MemRepository, Error> {
        let key: OptionFuture<_> = key.map(key::load).into();
        let key = key.await.transpose().map_err(Error::Key)?;
        Ok(MemRepository {
            id,
            key,
            containers: HashMap::new(),
        })
    }
}

#[async_trait::async_trait]
impl<'a> Repository for MemRepository {
    async fn insert(&mut self, rx: &mut Receiver<Bytes>) -> Result<Container, Error> {
        // Create a new memfd
        let opts = memfd::MemfdOptions::default().allow_sealing(true);
        let fd = opts.create(uuid::Uuid::new_v4().to_string()).map_err(|e| {
            Error::io(
                "Failed to create memfd",
                io::Error::new(ErrorKind::Other, e),
            )
        })?;

        // Write buffer to the memfd
        let mut file = unsafe { fs::File::from_raw_fd(fd.as_raw_fd()) };
        file.set_nonblocking();

        while let Some(r) = rx.recv().await {
            file.write_all(&r)
                .await
                .map_err(|e| Error::io("Failed copy npk", e))?;
        }

        file.seek(SeekFrom::Start(0))
            .await
            .map_err(|e| Error::io("Failed seek", e))?;

        // Seal the memfd
        let mut seals = memfd::SealsHashSet::new();
        seals.insert(memfd::FileSeal::SealShrink);
        seals.insert(memfd::FileSeal::SealGrow);
        fd.add_seals(&seals)
            .map_err(|e| Error::io("Failed to add seals", io::Error::new(ErrorKind::Other, e)))?;
        fd.add_seal(memfd::FileSeal::SealSeal)
            .map_err(|e| Error::io("Failed to add seals", io::Error::new(ErrorKind::Other, e)))?;

        // Forget fd - it's owned by file
        fd.into_raw_fd();

        file.set_blocking();
        let file = BufReader::new(file.into_std().await);

        // Load npk
        debug!("Loading buffer");
        let npk = npk::Npk::from_reader(file, self.key.as_ref())
            .map_err(|e| Error::Npk("Memory".into(), e))?;
        let manifest = npk.manifest();
        let container = Container::new(manifest.name.clone(), manifest.version.clone());

        if self.containers.contains_key(&container) {
            Err(Error::InstallDuplicate(container))
        } else {
            self.containers.insert(container.clone(), Arc::new(npk));
            info!("Loaded {} into {}", container, self.id);
            Ok(container)
        }
    }

    async fn remove(&mut self, container: &Container) -> Result<(), Error> {
        self.containers.remove(container);
        Ok(())
    }

    fn get(&self, container: &Container) -> Option<Arc<Npk>> {
        self.containers.get(container).cloned()
    }

    fn containers(&self) -> Vec<Arc<Npk>> {
        self.containers.values().cloned().collect()
    }

    fn list(&self) -> Vec<Container> {
        self.containers.keys().cloned().collect()
    }

    fn key(&self) -> Option<&PublicKey> {
        self.key.as_ref()
    }
}
