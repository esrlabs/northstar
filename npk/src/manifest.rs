// Copyright (c) 2019 - 2020 ESRLabs
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

use lazy_static::lazy_static;
use serde::{
    de::{Deserializer, Visitor},
    ser::{SerializeMap, Serializer},
    Deserialize, Serialize,
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;
use tokio::fs;

/// A container version. Versions follow the semver format
#[derive(Clone, PartialOrd, Hash, Eq, PartialEq)]
pub struct Version(pub semver::Version);

pub type Name = String;

impl Version {
    #[allow(dead_code)]
    pub fn parse(s: &str) -> Result<Version, semver::SemVerError> {
        Ok(Version(semver::Version::parse(s)?))
    }
}

impl Default for Version {
    fn default() -> Version {
        Version(semver::Version::new(0, 0, 0))
    }
}

/// Serde serialization for `Version`
impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

/// Serde deserialization for `Version`
impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VersionVisitor;

        impl<'de> Visitor<'de> for VersionVisitor {
            type Value = Version;
            fn visit_str<E>(self, str_data: &str) -> Result<Version, E>
            where
                E: serde::de::Error,
            {
                semver::Version::parse(str_data).map(Version).map_err(|_| {
                    serde::de::Error::invalid_value(::serde::de::Unexpected::Str(str_data), &self)
                })
            }

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> ::std::fmt::Result {
                formatter.write_str("string v0.0.0")
            }
        }

        deserializer.deserialize_str(VersionVisitor)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OnExit {
    /// Container is restarted n number and not started anymore after n exits
    #[serde(rename = "restart")]
    Restart(u32),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CGroupMem {
    /// Limit im bytes
    pub limit: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CGroupCpu {
    /// CPU shares assigned to this container. CGroups cpu divide
    /// the ressource CPU into 1024 shares
    pub shares: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CGroups {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem: Option<CGroupMem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CGroupCpu>,
}

#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub enum MountFlag {
    /// Bind mount
    #[serde(rename = "rw")]
    Rw,
    // Mount noexec
    // #[serde(rename = "noexec")]
    // NoExec,
    // Mount noexec
    // #[serde(rename = "nosuid")]
    // NoSuid,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Dev {
    #[serde(rename = "minimal")]
    Minimal,
    #[serde(rename = "full")]
    Full,
}

/// Mounts
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Mount {
    Resource {
        name: String,
        version: Version,
        dir: PathBuf,
    },
    Bind {
        host: PathBuf,
        flags: HashSet<MountFlag>,
    },
    /// Mount /dev with flavor `dev`
    Dev {
        dev: Dev,
    },
    /// Mount a host directory optionally RW to `target`
    Persist {
        flags: HashSet<MountFlag>,
    },
    Tmpfs {
        size: String,
    },
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Name of container
    pub name: Name,
    /// Container version
    pub version: Version,
    /// Path to init
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init: Option<PathBuf>,
    /// Additional arguments for the application invocation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    /// Environment passed to container
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,
    /// Autostart this container upon north startup
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autostart: Option<bool>,
    /// Action on application exit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_exit: Option<OnExit>,
    /// CGroup config
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroups: Option<CGroups>,
    /// Seccomp configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<HashMap<String, String>>,
    /// Number of instances to mount of this container
    /// The name get's extended with the instance id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instances: Option<u32>,
    /// List of bind mounts and resources
    #[serde(with = "MountsSerialization")]
    #[serde(default)]
    pub mounts: HashMap<PathBuf, Mount>,
}

struct MountsSerialization;

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum MountSource {
    Resource {
        resource: String,
    },
    Tmpfs {
        #[serde(deserialize_with = "deserialize_tmpfs_size")]
        size: String,
    },
    Bind {
        host: PathBuf,
        #[serde(default)]
        flags: HashSet<MountFlag>,
    },
    Dev {
        dev: Dev,
    },
    Persist {
        #[serde(default)]
        flags: HashSet<MountFlag>,
    },
}

fn deserialize_tmpfs_size<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct SizeVisitor;

    impl<'de> Visitor<'de> for SizeVisitor {
        type Value = String;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a number of bytes or a string with the size (e.g. 25M)")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
            Ok(format!("{}", v))
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            // check if the string is correctly formatted as size in tmpfs(5)
            lazy_static! {
                static ref TMPFS_SIZE: regex::Regex =
                    regex::Regex::new(r"^\d+(?i:k|m|g)?$").expect("Wrong regex");
            }
            if TMPFS_SIZE.is_match(v) {
                Ok(v.to_owned())
            } else {
                Err(E::custom("Wrong format for tmpfs size parameter"))
            }
        }
    }

    deserializer.deserialize_any(SizeVisitor)
}

impl MountsSerialization {
    fn serialize<S>(mounts: &HashMap<PathBuf, Mount>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(mounts.len()))?;
        for (target, mount) in mounts {
            match mount {
                Mount::Bind { host, flags } => map.serialize_entry(
                    &target,
                    &MountSource::Bind {
                        host: host.clone(),
                        flags: flags.clone(),
                    },
                )?,
                Mount::Dev { dev } => {
                    map.serialize_entry(&target, &MountSource::Dev { dev: dev.clone() })?
                }
                Mount::Persist { flags } => map.serialize_entry(
                    &target,
                    &MountSource::Persist {
                        flags: flags.clone(),
                    },
                )?,
                Mount::Resource { name, version, dir } => map.serialize_entry(
                    &target,
                    &MountSource::Resource {
                        resource: format!("{}:{}{}", name, version, dir.display()),
                    },
                )?,
                Mount::Tmpfs { size } => {
                    map.serialize_entry(&target, &MountSource::Tmpfs { size: size.clone() })?
                }
            }
        }
        map.end()
    }

    fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<PathBuf, Mount>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MountVectorVisitor;
        impl<'de> Visitor<'de> for MountVectorVisitor {
            type Value = HashMap<PathBuf, Mount>;

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut entries = HashMap::<PathBuf, Mount>::new();
                while let Some((target, source)) = map.next_entry()? {
                    if entries.contains_key(&target) {
                        return Err(serde::de::Error::custom(format!(
                            "Duplicate mountpoint: {:?}",
                            target
                        )));
                    }
                    entries.insert(
                        target,
                        match source {
                            MountSource::Bind { host, flags } => Mount::Bind { host, flags },
                            MountSource::Dev { dev } => Mount::Dev { dev },
                            MountSource::Tmpfs { size } => Mount::Tmpfs { size },
                            MountSource::Persist { flags } => Mount::Persist { flags },
                            MountSource::Resource { resource } => {
                                lazy_static! {
                                    static ref RE: regex::Regex = regex::Regex::new(
                                        r"(?P<name>\w+):(?P<version>[\d.]+)(?P<dir>[\w/]+)?"
                                    )
                                    .expect("Invalid regex");
                                }

                                let caps = RE.captures(&resource).ok_or_else(|| {
                                    serde::de::Error::custom(format!(
                                        "Invalid resource: {}",
                                        resource
                                    ))
                                })?;

                                let name = caps.name("name").unwrap().as_str().to_string();
                                let version =
                                    Version::parse(caps.name("version").unwrap().as_str())
                                        .map_err(serde::de::Error::custom)?;
                                let dir =
                                    PathBuf::from(caps.name("dir").map_or("/", |m| m.as_str()));

                                Mount::Resource { name, version, dir }
                            }
                        },
                    );
                }
                Ok(entries)
            }

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> ::std::fmt::Result {
                formatter.write_str("{ /path/a: Bind {} | Persist {} | Resource {}, /path/b: ... }")
            }
        }

        deserializer.deserialize_map(MountVectorVisitor)
    }
}

#[derive(Error, Debug)]
pub enum ManifestError {
    #[error("Invalid manifest ({0})")]
    MalformedManifest(String),
    #[error("Missing attribute: {0}")]
    CouldNotParse(String),
}

impl Manifest {
    fn verify(&self) -> Result<(), ManifestError> {
        // TODO: check for none on env, autostart, cgroups, seccomp, instances
        if self.init.is_none() && self.args.is_some() {
            return Err(ManifestError::MalformedManifest(
                "Arguments not allowed in resource container".to_string(),
            ));
        }
        Ok(())
    }

    pub async fn from_path(f: &Path) -> Result<Manifest, ManifestError> {
        let f = f.to_owned();
        let manifest = fs::read_to_string(&f).await.map_err(|_| {
            ManifestError::CouldNotParse(format!("Failed to read manifest from {}", f.display()))
        })?;
        let manifest: Manifest = Manifest::from_str(&manifest)?;
        manifest.verify()?;
        Ok(manifest)
    }

    /// used to find out if this manifest describes a resource container
    pub fn is_resource(&self) -> bool {
        self.init.is_none()
    }
}

impl FromStr for Manifest {
    type Err = ManifestError;
    fn from_str(s: &str) -> Result<Manifest, ManifestError> {
        let parse_res: Result<Manifest, ManifestError> = serde_yaml::from_str(s)
            .map_err(|_| ManifestError::CouldNotParse("Failed to parse manifest".to_string()));
        if let Ok(manifest) = &parse_res {
            manifest.verify()?;
        }
        parse_res
    }
}

#[cfg(test)]
mod tests {
    use crate::manifest::*;
    use anyhow::{anyhow, Result};

    #[tokio::test]
    async fn parse() -> Result<()> {
        use std::{fs::File, io::Write, path::PathBuf};

        let file = tempfile::NamedTempFile::new()?;
        let path = file.path();
        let m = "
name: hello
version: 0.0.0
init: /binary
args:
    - one
    - two
env:
    LD_LIBRARY_PATH: /lib
mounts:
    /lib:
      host: /lib
      flags:
          - rw
    /data: {}
    /data_rw:
      flags:
          - rw
    /resource:
        resource: bla:1.0.0/bin/foo
    /tmpfs:
        size: 42
    /big_tmpfs:
        size: 42G
    /dev:
        dev: minimal
autostart: true
cgroups:
  mem:
    limit: 30
  cpu:
    shares: 100
seccomp:
    fork: 1
    waitpid: 1
log:
    tag: test
    buffer:
        custom: 8
";

        let mut file = File::create(path)?;
        file.write_all(m.as_bytes())?;
        drop(file);

        let manifest = Manifest::from_path(&PathBuf::from(path)).await?;

        assert_eq!(manifest.init, Some(PathBuf::from("/binary")));
        assert_eq!(manifest.name, "hello");
        let args = manifest.args.ok_or_else(|| anyhow!("Missing args"))?;
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "one");
        assert_eq!(args[1], "two");

        assert!(manifest.autostart.unwrap());
        let env = manifest.env.ok_or_else(|| anyhow!("Missing env"))?;
        assert_eq!(
            env.get("LD_LIBRARY_PATH"),
            Some("/lib".to_string()).as_ref()
        );
        let mut mounts = HashMap::new();
        mounts.insert(
            PathBuf::from("/lib"),
            Mount::Bind {
                host: PathBuf::from("/lib"),
                flags: [MountFlag::Rw].iter().cloned().collect(),
            },
        );
        mounts.insert(
            PathBuf::from("/data"),
            Mount::Persist {
                flags: HashSet::new(),
            },
        );
        mounts.insert(
            PathBuf::from("/data_rw"),
            Mount::Persist {
                flags: [MountFlag::Rw].iter().cloned().collect(),
            },
        );
        mounts.insert(
            PathBuf::from("/resource"),
            Mount::Resource {
                name: "bla".to_string(),
                version: Version::parse("1.0.0")?,
                dir: PathBuf::from("/bin/foo"),
            },
        );
        mounts.insert(
            PathBuf::from("/tmpfs"),
            Mount::Tmpfs {
                size: "42".to_string(),
            },
        );
        mounts.insert(
            PathBuf::from("/big_tmpfs"),
            Mount::Tmpfs {
                size: "42G".to_string(),
            },
        );
        mounts.insert(PathBuf::from("/dev"), Mount::Dev { dev: Dev::Minimal });
        assert_eq!(manifest.mounts, mounts);
        assert_eq!(
            manifest.cgroups,
            Some(CGroups {
                mem: Some(CGroupMem { limit: 30 }),
                cpu: Some(CGroupCpu { shares: 100 }),
            })
        );

        let mut seccomp = HashMap::new();
        seccomp.insert("fork".to_string(), "1".to_string());
        seccomp.insert("waitpid".to_string(), "1".to_string());
        assert_eq!(manifest.seccomp, Some(seccomp));

        Ok(())
    }

    #[tokio::test]
    async fn dupllicate_mount() -> Result<()> {
        use std::{fs::File, io, path::PathBuf};

        let file = tempfile::NamedTempFile::new()?;
        let path = file.path();
        let m = "
name: hello
version: 0.0.0
init: /binary
mounts:
    /lib:
      host: /foo
      flags:
          - rw
    /lib:
      host: /bar
      flags:
          - rw
";

        let mut file = File::create(path)?;
        io::copy(&mut m.as_bytes(), &mut file)?;
        drop(file);

        assert!(Manifest::from_path(&PathBuf::from(path)).await.is_err());

        Ok(())
    }

    #[test]
    fn serialize_back_and_forth() -> Result<()> {
        let m = "
name: hello
version: 0.0.0
init: /binary
args:
    - one
    - two
env:
    LD_LIBRARY_PATH: /lib
mounts:
    /lib:
      host: /lib
      flags:
          - rw
    /data: {}
    /data_rw:
      flags:
          - rw
    /resource:
        resource: bla:1.0.0/bin/foo
    /tmpfs:
        size: 42
    /big_tmpfs:
        size: 42G
    /dev:
        dev: minimal
autostart: true
cgroups:
  mem:
    limit: 30
  cpu:
    shares: 100
seccomp:
    fork: 1
    waitpid: 1
log:
    tag: test
    buffer:
        custom: 8
";

        let manifest = serde_yaml::from_str::<Manifest>(m)?;
        println!("{}", serde_yaml::to_string(&manifest)?);
        let deserialized = serde_yaml::from_str::<Manifest>(&serde_yaml::to_string(&manifest)?)?;

        assert_eq!(manifest, deserialized);
        Ok(())
    }

    #[test]
    fn version() -> Result<()> {
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
}
