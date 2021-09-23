use crate::common::{
    name::{InvalidNameChar, Name},
    version::Version,
};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt::{self, Display},
    sync::Arc,
};
use thiserror::Error;

/// Container identification
#[derive(Clone, Eq, PartialOrd, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub struct Container {
    #[serde(flatten)]
    inner: Arc<Inner>,
}

impl Container {
    /// Construct a new container
    pub fn new(name: Name, version: Version) -> Container {
        Container {
            inner: Arc::new(Inner { name, version }),
        }
    }

    /// Container name
    pub fn name(&self) -> &Name {
        &self.inner.name
    }

    /// Container version
    pub fn version(&self) -> &Version {
        &self.inner.version
    }
}

/// Container error
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Missing container name")]
    MissingName,
    #[error("Invalid container name")]
    InvalidName(InvalidNameChar),
    #[error("Missing container version")]
    MissingVersion,
    #[error("Invalid container version")]
    InvalidVersion,
}

impl Display for Container {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.inner.name, self.inner.version,)
    }
}

impl From<InvalidNameChar> for Error {
    fn from(e: InvalidNameChar) -> Self {
        Error::InvalidName(e)
    }
}

impl TryFrom<&str> for Container {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut split = value.split(':');
        let name = split
            .next()
            .ok_or(Error::MissingName)?
            .to_string()
            .try_into()
            .map_err(Error::InvalidName)?;
        let version = split.next().ok_or(Error::MissingVersion)?;
        let version = Version::parse(version).map_err(|_| Error::InvalidVersion)?;
        Ok(Container::new(name, version))
    }
}

impl TryFrom<&Container> for Container {
    type Error = Error;

    fn try_from(container: &Container) -> Result<Self, Self::Error> {
        Ok(container.clone())
    }
}

impl<E: Into<Error>, N: TryInto<Name, Error = E>, V: ToString> TryFrom<(N, V)> for Container {
    type Error = Error;

    fn try_from((name, version): (N, V)) -> Result<Self, Self::Error> {
        let name = name.try_into().map_err(Into::into)?;
        let version = Version::parse(&version.to_string()).map_err(|_| Error::InvalidVersion)?;
        Ok(Container::new(name, version))
    }
}

#[derive(Eq, PartialOrd, PartialEq, Debug, Hash, Serialize, Deserialize)]
struct Inner {
    name: Name,
    version: Version,
}

#[test]
fn try_from() {
    assert_eq!(
        Container::new("test".try_into().unwrap(), Version::parse("0.0.1").unwrap()),
        "test:0.0.1".try_into().unwrap()
    );
}
