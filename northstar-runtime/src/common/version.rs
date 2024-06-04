use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    fmt::{self, Display},
    str::FromStr,
};
use thiserror::Error;

/// Parsing error
#[derive(Error, Debug)]
pub struct ParseError {
    #[from]
    source: semver::Error,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)
    }
}

/// Container version
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Version {
    /// Major
    pub major: u64,
    /// Minor
    pub minor: u64,
    /// Patch
    pub patch: u64,
}

impl Version {
    /// Construct a new version
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse a string into a version
    pub fn parse(version: &str) -> Result<Self, ParseError> {
        semver::Version::parse(version)
            .map(|ref version| version.into())
            .map_err(|source| ParseError { source })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl From<&semver::Version> for Version {
    fn from(version: &semver::Version) -> Self {
        Self {
            major: version.major,
            minor: version.minor,
            patch: version.patch,
        }
    }
}

impl From<&Version> for semver::Version {
    fn from(version: &Version) -> Self {
        semver::Version::new(version.major, version.minor, version.patch)
    }
}

impl<T> From<(T, T, T)> for Version
where
    T: Into<u64>,
{
    fn from((major, minor, patch): (T, T, T)) -> Self {
        Self {
            major: major.into(),
            minor: minor.into(),
            patch: patch.into(),
        }
    }
}

impl FromStr for Version {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        semver::Version::parse(s)
            .map(|ref version| version.into())
            .map_err(|source| ParseError { source })
    }
}

impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Version::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.major > other.major {
            Ordering::Greater
        } else if self.major < other.major {
            Ordering::Less
        } else if self.minor > other.minor {
            Ordering::Greater
        } else if self.minor < other.minor {
            Ordering::Less
        } else if self.patch > other.patch {
            Ordering::Greater
        } else if self.patch < other.patch {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    }
}

/// Container version requirement
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct VersionReq {
    inner: semver::VersionReq,
}

impl VersionReq {
    /// Parse a string into a version requirement
    pub fn parse(text: &str) -> Result<VersionReq, ParseError> {
        Ok(VersionReq {
            inner: semver::VersionReq::parse(text)?,
        })
    }

    /// Check whether the given version satisfies this requirement
    pub fn matches(&self, version: &Version) -> bool {
        self.inner.matches(&semver::Version::from(version))
    }
}

impl FromStr for VersionReq {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(VersionReq {
            inner: semver::VersionReq::from_str(s)?,
        })
    }
}

impl Display for VersionReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl Serialize for VersionReq {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.inner.to_string())
    }
}

impl<'de> Deserialize<'de> for VersionReq {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        VersionReq::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[test]
fn version() -> anyhow::Result<()> {
    let v1 = Version::parse("1.0.0")?;
    let v2 = Version::parse("2.0.0")?;
    let v3 = Version::parse("3.0.0")?;
    assert!(v2 > v1);
    assert!(v2 < v3);
    let v1_1 = Version::parse("1.1.0")?;
    assert!(v1_1 > v1);
    let v1_1_1 = Version::parse("1.1.1")?;
    assert!(v1_1_1 > v1_1);
    Ok(())
}
