use crate::common::version::VersionReq;
use itertools::Itertools;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt::{self, Display},
    sync::Arc,
};
use thiserror::Error;

use super::{
    name::{Name, NameError},
    version::Version,
};

/// Container identification
#[derive(Clone, Eq, PartialOrd, Ord, PartialEq, Debug, Hash, JsonSchema)]
pub struct Container {
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
    #[error("missing container name")]
    MissingName,
    #[error("invalid container name")]
    InvalidName(NameError),
    #[error("missing container version")]
    MissingVersion,
    #[error("invalid container version")]
    InvalidVersion,
}

impl Display for Container {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.inner.name, self.inner.version,)
    }
}

impl From<NameError> for Error {
    fn from(e: NameError) -> Self {
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

impl Serialize for Container {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}:{}", self.inner.name, self.inner.version))
    }
}

impl<'de> Deserialize<'de> for Container {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Container::try_from(value.as_str()).map_err(serde::de::Error::custom)
    }
}

#[derive(Eq, PartialOrd, PartialEq, Ord, Debug, Hash, Serialize, Deserialize, JsonSchema)]
struct Inner {
    name: Name,
    version: Version,
}

/// Find the resource container that best matches the given version requirement.
pub fn find_resource(
    name: &Name,
    version_req: &VersionReq,
    candidates: &mut impl Iterator<Item = Container>,
) -> Option<Container> {
    candidates
        .filter(|c| c.name() == name && version_req.matches(c.version()))
        .sorted_by(|c1, c2| c1.version().cmp(c2.version()))
        .next()
}

#[test]
fn try_from() {
    assert_eq!(
        Container::new("test".try_into().unwrap(), Version::parse("0.0.1").unwrap()),
        "test:0.0.1".try_into().unwrap()
    );
}

#[test]
fn invalid_name() {
    assert!(Container::try_from("test\0:0.0.1").is_err());
    assert!(Container::try_from("tes%t:0.0.1").is_err());
}

#[test]
fn schema() {
    schemars::schema_for!(Container);
}

#[test]
fn find_newest_resource() {
    use std::str::FromStr;

    let old = Container::try_from("test:0.0.1").unwrap();
    let new = Container::try_from("test:0.0.2").unwrap();
    let other = Container::try_from("other:1.0.0").unwrap();
    let containers = [old, new.clone(), other];
    let resource = find_resource(
        &Name::try_from("test").unwrap(),
        &VersionReq::from_str(">=0.0.2").unwrap(),
        &mut containers.into_iter(),
    );
    assert!(resource.is_some());
    assert_eq!(resource.unwrap(), new);
}

#[test]
fn cannot_find_newer_resource() {
    use std::str::FromStr;

    let old = Container::try_from("test:0.0.1").unwrap();
    let new = Container::try_from("test:0.0.2").unwrap();
    let other = Container::try_from("other:1.0.0").unwrap();
    let containers = [old, new, other];
    let resource = find_resource(
        &Name::try_from("test").unwrap(),
        &VersionReq::from_str(">=0.0.3").unwrap(),
        &mut containers.into_iter(),
    );
    assert!(resource.is_none());
}
