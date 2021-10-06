use super::{
    error::{Context, Error},
    key::{self, PublicKey},
    Container,
};
use crate::{
    npk::npk::{self},
    runtime::pipe::RawFdExt,
};
use bytes::Bytes;
use floating_duration::TimeAsFloat;
use futures::future::OptionFuture;
use log::{debug, info};
use mpsc::Receiver;
use std::{
    collections::HashMap,
    fmt,
    io::{BufReader, SeekFrom},
    os::unix::prelude::{AsRawFd, FromRawFd, IntoRawFd},
    path::{Path, PathBuf},
};
use tokio::{
    fs::{self},
    io::{AsyncSeekExt, AsyncWriteExt},
    sync::mpsc,
    time::Instant,
};

pub(super) type Npk = crate::npk::npk::Npk<BufReader<std::fs::File>>;

#[async_trait::async_trait]
pub(super) trait Repository: fmt::Debug {
    /// Stream an npk from `rx` into the repository and load it
    async fn insert(&mut self, rx: &mut Receiver<Bytes>) -> Result<Container, Error>;

    /// Add container from repository if present
    async fn remove(&mut self, container: &Container) -> Result<(), Error>;

    /// Return npk matching container if present
    fn get(&self, container: &Container) -> Option<&Npk>;

    /// Key of this repository
    fn key(&self) -> Option<&PublicKey>;

    /// All containers in this repository
    fn containers(&self) -> Vec<&Npk>;
}

/// Repository backed by a directory
#[derive(Debug)]
pub(super) struct DirRepository {
    dir: PathBuf,
    key: Option<PublicKey>,
    containers: HashMap<Container, (PathBuf, Npk)>,
}

impl DirRepository {
    pub async fn new(dir: &Path, key: Option<&Path>) -> Result<DirRepository, Error> {
        let mut containers = HashMap::new();

        info!("Loading repository {}", dir.display());

        let key: OptionFuture<_> = key.map(key::load).into();
        let key = key.await.transpose().map_err(Error::Key)?;

        let mut readir = fs::read_dir(&dir).await.context("Repository read dir")?;

        let start = Instant::now();
        while let Ok(Some(entry)) = readir.next_entry().await {
            let file = entry.path();
            debug!(
                "Loading {}{}",
                file.display(),
                if key.is_some() { " [verified]" } else { "" }
            );
            let reader = std::fs::File::open(&file).context("Failed to open npk")?;
            let reader = std::io::BufReader::new(reader);
            let npk = crate::npk::npk::Npk::from_reader(reader, key.as_ref())
                .map_err(|e| Error::Npk(file.display().to_string(), e))?;
            let name = npk.manifest().name.clone();
            let version = npk.manifest().version.clone();
            let container = Container::new(name, version);
            containers.insert(container, (file, npk));
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
            .context("Failed create npk in repository")?;
        while let Some(r) = rx.recv().await {
            file.write_all(&r).await.context("Failed to write npk")?;
        }
        file.flush().await.context("Failed to flush npk")?;
        drop(file);

        debug!("Loading {}", dest.display());
        let npk = match Npk::from_path(dest.as_path(), self.key.as_ref())
            .map_err(|e| Error::Npk(dest.display().to_string(), e))
        {
            Ok(n) => Ok(n),
            Err(e) => {
                fs::remove_file(&dest)
                    .await
                    .context("Remove file from repository")?;
                Err(e)
            }
        }?;
        let name = npk.manifest().name.clone();
        let version = npk.manifest().version.clone();
        let container = Container::new(name, version);
        if self.containers.contains_key(&container) {
            fs::remove_file(&dest)
                .await
                .context("Remove file from repository")?;
            Err(Error::InstallDuplicate(container.clone()))
        } else {
            self.containers.insert(container.clone(), (dest, npk));
            info!("Loaded {}", container);
            Ok(container)
        }
    }

    async fn remove(&mut self, container: &Container) -> Result<(), Error> {
        if let Some((path, npk)) = self.containers.remove(container) {
            debug!("Removing {}", path.display());
            drop(npk);
            fs::remove_file(path)
                .await
                .context("Failed to remove npk")
                .map(drop)
        } else {
            Ok(())
        }
    }

    fn get(&self, container: &Container) -> Option<&Npk> {
        self.containers.get(container).map(|(_, npk)| npk)
    }

    fn key(&self) -> Option<&PublicKey> {
        self.key.as_ref()
    }

    fn containers(&self) -> Vec<&Npk> {
        self.containers.values().map(|(_, npk)| npk).collect()
    }
}

/// In memory repository
#[derive(Debug)]
pub(super) struct MemRepository {
    key: Option<PublicKey>,
    containers: HashMap<Container, Npk>,
}

impl MemRepository {
    pub async fn new(key: Option<&Path>) -> Result<MemRepository, Error> {
        let key: OptionFuture<_> = key.map(key::load).into();
        let key = key.await.transpose().map_err(Error::Key)?;
        Ok(MemRepository {
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
        let fd = opts
            .create(uuid::Uuid::new_v4().to_string())
            .context("Failed to create memfd")?;

        // Write buffer to the memfd
        let mut file = unsafe { fs::File::from_raw_fd(fd.as_raw_fd()) };
        file.set_nonblocking();

        while let Some(r) = rx.recv().await {
            file.write_all(&r).await.context("Failed copy npk")?;
        }

        file.seek(SeekFrom::Start(0)).await.context("Failed seek")?;

        // Seal the memfd
        let mut seals = memfd::SealsHashSet::new();
        seals.insert(memfd::FileSeal::SealShrink);
        seals.insert(memfd::FileSeal::SealGrow);
        fd.add_seals(&seals)
            .and_then(|_| fd.add_seal(memfd::FileSeal::SealSeal))
            .context("Failed to add seals")?;

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
            self.containers.insert(container.clone(), npk);
            info!("Loaded {}", container);
            Ok(container)
        }
    }

    async fn remove(&mut self, container: &Container) -> Result<(), Error> {
        self.containers.remove(container);
        Ok(())
    }

    fn get(&self, container: &Container) -> Option<&Npk> {
        self.containers.get(container)
    }

    fn containers(&self) -> Vec<&Npk> {
        self.containers.values().collect()
    }

    fn key(&self) -> Option<&PublicKey> {
        self.key.as_ref()
    }
}
