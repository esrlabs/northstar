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

use anyhow::{anyhow, Context, Result};
use async_std::{fs, path::Path};
use lazy_static::lazy_static;
use serde::{
    de::{Deserializer, Visitor},
    ser::{SerializeMap, Serializer},
    Deserialize, Serialize,
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    str::FromStr,
};
use thiserror::Error;

/// A container version. Versions follow the semver format
#[derive(Clone, PartialOrd, Hash, Eq, PartialEq)]
pub struct Version(pub semver::Version);

pub type Name = String;

impl Version {
    #[allow(dead_code)]
    pub fn parse(s: &str) -> Result<Version> {
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

#[derive(Clone, Eq, PartialEq, Debug, Serialize)]
pub enum Mount {
    Resource {
        target: std::path::PathBuf,
        name: String,
        version: Version,
        dir: std::path::PathBuf,
    },
    Bind {
        target: std::path::PathBuf,
        host: std::path::PathBuf,
        flags: HashSet<MountFlag>,
    },
    Persist {
        target: std::path::PathBuf,
        flags: HashSet<MountFlag>,
    },
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Name of container
    pub name: Name,
    /// Container version
    pub version: Version,
    /// Target arch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Path to init
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init: Option<std::path::PathBuf>,
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
    pub mounts: Vec<Mount>,
}

struct MountsSerialization;

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum MountSource {
    Resource {
        resource: String,
    },
    Bind {
        host: std::path::PathBuf,
        #[serde(default)]
        flags: HashSet<MountFlag>,
    },
    Persist {
        #[serde(default)]
        flags: HashSet<MountFlag>,
    },
}

impl MountsSerialization {
    fn serialize<S>(mounts: &[Mount], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(mounts.len()))?;
        for mount in mounts {
            match mount {
                Mount::Bind {
                    target,
                    host,
                    flags,
                } => map.serialize_entry(
                    &target,
                    &MountSource::Bind {
                        host: host.clone(),
                        flags: flags.clone(),
                    },
                )?,
                Mount::Persist { target, flags } => map.serialize_entry(
                    &target,
                    &MountSource::Persist {
                        flags: flags.clone(),
                    },
                )?,
                Mount::Resource {
                    target,
                    name,
                    version,
                    dir,
                } => map.serialize_entry(
                    &target,
                    &MountSource::Resource {
                        resource: format!("{}:{}{}", name, version, dir.display()),
                    },
                )?,
            }
        }
        map.end()
    }

    fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Mount>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MountVectorVisitor;
        impl<'de> Visitor<'de> for MountVectorVisitor {
            type Value = Vec<Mount>;

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut entries = Vec::new();
                while let Some((target, source)) = map.next_entry()? {
                    entries.push(match source {
                        MountSource::Bind { host, flags } => Mount::Bind {
                            target,
                            host,
                            flags,
                        },
                        MountSource::Persist { flags } => Mount::Persist { target, flags },
                        MountSource::Resource { resource } => {
                            lazy_static! {
                                static ref RE: regex::Regex = regex::Regex::new(
                                    r"(?P<name>\w+):(?P<version>[\d.]+)(?P<dir>[\w/]+)?"
                                )
                                .expect("Invalid regex");
                            }

                            let caps = RE
                                .captures(&resource)
                                .ok_or_else(|| anyhow!("Invalid resource: {}", resource))
                                .map_err(serde::de::Error::custom)?;

                            let name = caps.name("name").unwrap().as_str().to_string();
                            let version = Version::parse(caps.name("version").unwrap().as_str())
                                .map_err(serde::de::Error::custom)?;
                            let dir = std::path::PathBuf::from(
                                caps.name("dir").map_or("/", |m| m.as_str()),
                            );

                            Mount::Resource {
                                target,
                                name,
                                version,
                                dir,
                            }
                        }
                    })
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

    pub async fn from_path(f: &Path) -> Result<Manifest> {
        let f = f.to_owned();
        let manifest = fs::read_to_string(&f)
            .await
            .with_context(|| format!("Failed to read manifest from {}", f.display()))?;
        let manifest: Manifest = Manifest::from_str(&manifest)?;
        manifest.verify()?;
        Ok(manifest)
    }

    /// used to find out if this manifest describes a resource container
    pub fn is_resource_image(&self) -> bool {
        self.init.is_none()
    }
}

impl FromStr for Manifest {
    type Err = ManifestError;
    fn from_str(s: &str) -> std::result::Result<Manifest, ManifestError> {
        let parse_res: std::result::Result<Manifest, ManifestError> = serde_yaml::from_str(s)
            .map_err(|_| ManifestError::CouldNotParse("Failed to parse manifest".to_string()));
        if let Ok(manifest) = &parse_res {
            manifest.verify()?;
        }
        parse_res
    }
}

#[async_std::test]
async fn parse() -> Result<()> {
    use anyhow::anyhow;
    use async_std::path::PathBuf;
    use std::{fs::File, io::Write};

    let file = tempfile::NamedTempFile::new()?;
    let path = file.path();
    let m = "
name: hello
version: 0.0.0
arch: aarch64-linux-android
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
    /here/we/go:
        resource: bla:1.0.0/bin/foo
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

    assert_eq!(manifest.init, Some(std::path::PathBuf::from("/binary")));
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
    let mounts = vec![
        Mount::Bind {
            target: std::path::PathBuf::from("/lib"),
            host: std::path::PathBuf::from("/lib"),
            flags: [MountFlag::Rw].iter().cloned().collect(),
        },
        Mount::Persist {
            target: std::path::PathBuf::from("/data"),
            flags: HashSet::new(),
        },
        Mount::Persist {
            target: std::path::PathBuf::from("/data_rw"),
            flags: [MountFlag::Rw].iter().cloned().collect(),
        },
        Mount::Resource {
            target: std::path::PathBuf::from("/here/we/go"),
            name: "bla".to_string(),
            version: Version::parse("1.0.0")?,
            dir: PathBuf::from("/bin/foo").into(),
        },
    ];
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

#[test]
fn serialize_back_and_forth() -> Result<()> {
    let m = "
name: hello
version: 0.0.0
arch: aarch64-linux-android
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
    /here/we/go:
        resource: bla:1.0.0/bin/foo
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
    let string_copie = serde_yaml::to_string(&manifest)?;
    let manifest_copie = serde_yaml::from_str::<Manifest>(&string_copie)?;

    assert_eq!(manifest, manifest_copie);
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
