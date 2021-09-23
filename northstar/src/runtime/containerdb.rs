//! Defines [ContainerDB], a struct to manage containers
//!
//! Northstar organizes containers in repositories. Repositories can be any object that implements
//! the [Repository][crate::runtime::repository::Repository] trait.

use std::{collections::HashMap, ops::Deref, sync::Arc};

use bytes::Bytes;
use tokio::sync::mpsc::Receiver;

use crate::{
    common::container::Container,
    npk::manifest::Manifest,
    runtime::{
        error::Error,
        repository::{Repository, RepositoryId},
        state::Npk,
    },
};

/// Container Database
#[derive(Debug, Default)]
pub struct ContainerDB {
    // The repositories are stored together with their RepositoryId in a vector of tuples. This
    // vector is indexed is a way that it is possible to access it later using either a [Container]
    // or a [RepositoryId] as a key. The member `index_by_container` associates to each [Container]
    // the position in the vector corresponding to the repository that contains it. In the same
    // manner, `index_by_repository` contains the associated vector positons for each
    // [RepositoryId].
    index_by_repository: HashMap<RepositoryId, usize>,
    index_by_container: HashMap<Container, usize>,
    repositories: Vec<(RepositoryId, Box<dyn Repository>)>,
}

impl ContainerDB {
    /// Insert a new container repository into the database
    pub fn insert<R>(&mut self, id: RepositoryId, repository: R) -> Result<(), Error>
    where
        R: Repository + 'static,
    {
        // Check for repository index collition
        if self.index_by_repository.contains_key(&id) {
            return Err(Error::InvalidRepository(id));
        }

        // Check for container index collitions
        for container in repository.list() {
            if self.index_by_container.contains_key(&container) {
                return Err(Error::DuplicateContainer(container));
            }
        }

        // make the insertion
        let index = self.repositories.len();

        self.index_by_repository.insert(id.clone(), index);
        for container in repository.list() {
            self.index_by_container.insert(container, index);
        }

        self.repositories.push((id, Box::new(repository)));
        Ok(())
    }

    /// Find the container's manifest
    pub fn find_manifest(&self, container: &Container) -> Option<impl Deref<Target = Manifest>> {
        struct ManifestRef(Arc<Npk>);

        impl Deref for ManifestRef {
            type Target = Manifest;

            fn deref(&self) -> &Self::Target {
                self.0.manifest()
            }
        }

        self.find_repository(container)
            .and_then(|(_, repository)| repository.get(container))
            .map(ManifestRef)
    }

    /// Find the repository that contains the given container
    pub fn find_repository(
        &self,
        container: &Container,
    ) -> Option<&(RepositoryId, Box<dyn Repository>)> {
        self.index_by_container
            .get(container)
            .and_then(|&idx| self.repositories.get(idx))
    }

    /// Returns an iterator over all the containers
    pub fn containers(&self) -> impl Iterator<Item = Container> + '_ {
        self.repositories
            .iter()
            .map(|(_, repository)| repository.list())
            .flatten()
    }

    /// Returns an iterator over the repository ids
    pub fn repositories(&self) -> impl Iterator<Item = &RepositoryId> {
        self.repositories.iter().map(|(id, _)| id)
    }

    /// install container
    pub async fn install(
        &mut self,
        id: &RepositoryId,
        rx: &mut Receiver<Bytes>,
    ) -> Result<Container, Error> {
        let idx: usize = *self
            .index_by_repository
            .get(id)
            .ok_or_else(|| Error::InvalidRepository(id.clone()))?;

        let (_, repository) = &mut self.repositories[idx];

        let container = repository.insert(rx).await?;
        self.index_by_container.insert(container.clone(), idx);
        log::info!("Added {} into {}", container, id);
        Ok(container)
    }

    /// Uninstall container
    pub async fn uninstall(&mut self, container: &Container) -> Result<(), Error> {
        let idx = self
            .index_by_container
            .get(container)
            .ok_or_else(|| Error::InvalidContainer(container.clone()))?;

        let (id, repository) = &mut self.repositories[*idx];
        repository.remove(container).await?;

        // remove container index
        self.index_by_container.remove(container);
        log::info!("Removed {} from {}", container, id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use super::*;

    type MockRepository = HashMap<Container, usize>;

    #[async_trait::async_trait]
    impl Repository for MockRepository {
        async fn insert(
            &mut self,
            _rx: &mut tokio::sync::mpsc::Receiver<bytes::Bytes>,
        ) -> Result<crate::api::model::Container, Error> {
            todo!()
        }

        async fn remove(&mut self, _container: &crate::api::model::Container) -> Result<(), Error> {
            todo!()
        }

        fn get(&self, _container: &crate::api::model::Container) -> Option<Arc<Npk>> {
            todo!()
        }

        fn key(&self) -> Option<&crate::runtime::key::PublicKey> {
            todo!()
        }

        fn list(&self) -> Vec<crate::api::model::Container> {
            self.keys().cloned().collect()
        }
    }

    #[test]
    fn insert_empty_repository() {
        let mut db = ContainerDB::default();
        let repository = MockRepository::default();
        assert!(db.insert("mock".into(), repository).is_ok());
    }

    #[test]
    fn insert_repository_with_same_key() {
        let mut db = ContainerDB::default();
        let r1 = MockRepository::default();
        let r2 = MockRepository::default();
        assert!(db.insert("mock".into(), r1).is_ok());
        assert!(matches!(
            db.insert("mock".into(), r2),
            Err(Error::InvalidRepository(_))
        ));
    }

    #[test]
    fn insert_repositories_with_duplicate_containers() {
        let mut db = ContainerDB::default();
        let mut r1 = MockRepository::default();
        let mut r2 = MockRepository::default();
        let container = Container::new("dummy".try_into().unwrap(), "0.0.1".parse().unwrap());
        r1.insert(container.clone(), 42);
        r2.insert(container, 43);
        assert!(db.insert("r1".into(), r1).is_ok());
        assert!(matches!(
            db.insert("r2".into(), r2),
            Err(Error::DuplicateContainer(_))
        ));
    }
}
