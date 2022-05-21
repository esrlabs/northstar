use itertools::Itertools;
use schemars::JsonSchema;
use serde::{
    de::{Deserializer, Visitor},
    Deserialize, Serialize, Serializer,
};
use std::{collections::HashSet, fmt, str::FromStr};

use crate::common::{name::Name, non_nul_string::NonNulString, version::VersionReq};

/// Mount point
pub type MountPoint = NonNulString;

/// Resource mount configuration
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    /// Name of the resource container
    pub name: Name,
    /// Required version of the resource container
    pub version: VersionReq,
    /// Directory within the resource container
    pub dir: NonNulString,
    /// Mount options
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub options: MountOptions,
}

/// Bind mount configuration
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Bind {
    /// Path in the host filesystem
    pub host: NonNulString,
    /// Mount options
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub options: MountOptions,
}

/// Tmpfs configuration
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Tmpfs {
    /// Size in bytes
    #[serde(deserialize_with = "deserialize_tmpfs_size")]
    pub size: u64,
}

/// Mounts
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum Mount {
    /// Bind mount of a host dir with options
    #[serde(rename = "bind")]
    Bind(Bind),
    /// Use a minimal dev tree
    #[serde(rename = "dev")]
    Dev,
    /// Mount a rw host directory dedicated to this container rw
    #[serde(rename = "persist")]
    Persist,
    /// Mount proc
    #[serde(rename = "proc")]
    Proc,
    /// Mount a directory from a resource
    #[serde(rename = "resource")]
    Resource(Resource),
    /// Mount a tmpfs with size
    #[serde(rename = "tmpfs")]
    Tmpfs(Tmpfs),
}

#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize, JsonSchema)]
#[allow(missing_docs)]
/// Mount option
pub enum MountOption {
    /// Bind mount
    #[serde(rename = "rw")]
    Rw,
    // Mount noexec
    #[serde(rename = "noexec")]
    NoExec,
    // Mount nosuid
    #[serde(rename = "nosuid")]
    NoSuid,
    // Mount nodev
    #[serde(rename = "nodev")]
    NoDev,
    // Mount recursive
    #[serde(rename = "rec")]
    Rec,
}

impl FromStr for MountOption {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rw" => Ok(MountOption::Rw),
            "noexec" => Ok(MountOption::NoExec),
            "nosuid" => Ok(MountOption::NoSuid),
            "nodev" => Ok(MountOption::NoDev),
            "rec" => Ok(MountOption::Rec),
            _ => Err(format!("invalid mount option {}", s)),
        }
    }
}

impl fmt::Display for MountOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MountOption::Rw => write!(f, "rw"),
            MountOption::NoExec => write!(f, "noexec"),
            MountOption::NoSuid => write!(f, "nosuid"),
            MountOption::NoDev => write!(f, "nodev"),
            MountOption::Rec => write!(f, "rec"),
        }
    }
}

/// Mount option set
#[derive(Default, Clone, Eq, PartialEq, Debug, JsonSchema)]
pub struct MountOptions(HashSet<MountOption>);

impl std::ops::Deref for MountOptions {
    type Target = HashSet<MountOption>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for MountOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.iter().join(","))
    }
}

impl Serialize for MountOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.iter().map(ToString::to_string).join(","))
    }
}

impl FromIterator<MountOption> for MountOptions {
    fn from_iter<I: IntoIterator<Item = MountOption>>(iter: I) -> Self {
        MountOptions(iter.into_iter().collect())
    }
}

impl<'de> Deserialize<'de> for MountOptions {
    fn deserialize<D>(deserializer: D) -> Result<MountOptions, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MountOptionsVisitor;
        impl<'de> Visitor<'de> for MountOptionsVisitor {
            type Value = MountOptions;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("comma seperated mount options")
            }

            fn visit_str<E: serde::de::Error>(self, str_data: &str) -> Result<MountOptions, E> {
                let options = str_data.trim();
                if !options.is_empty() {
                    let iter = options.split(',');
                    let mut result = HashSet::with_capacity(iter.size_hint().0);
                    for opt in iter {
                        result.insert(
                            MountOption::from_str(opt.trim()).map_err(serde::de::Error::custom)?,
                        );
                    }
                    Ok(MountOptions(result))
                } else {
                    Ok(MountOptions::default())
                }
            }
        }

        deserializer.deserialize_str(MountOptionsVisitor)
    }
}

fn deserialize_tmpfs_size<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    struct SizeVisitor;

    impl<'de> Visitor<'de> for SizeVisitor {
        type Value = u64;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a number of bytes or a string with the size (e.g. 25M)")
        }

        fn visit_u64<E>(self, v: u64) -> Result<u64, E> {
            Ok(v)
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<u64, E> {
            use humanize_rs::bytes::Bytes;
            v.parse::<Bytes>()
                .map(|b| b.size() as u64)
                .map_err(serde::de::Error::custom)
        }
    }

    deserializer.deserialize_any(SizeVisitor)
}
