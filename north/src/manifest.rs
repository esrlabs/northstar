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

use anyhow::{anyhow, Context, Error, Result};
use async_std::{path::Path, task};
use serde::{
    de::{Deserializer, Visitor},
    ser::Serializer,
    Deserialize, Serialize,
};
use std::convert::TryFrom;
use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::File,
    str::FromStr,
};

/// A container version. Versions follow the semver format
#[derive(Clone, PartialOrd, Hash, Eq, PartialEq)]
pub struct Version(semver::Version);

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
    pub mem: Option<CGroupMem>,
    pub cpu: Option<CGroupCpu>,
}

// TODO: Remove?
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    pub name: Name,
    pub version: Version,
    pub dir: std::path::PathBuf,
    pub mountpoint: std::path::PathBuf,
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Resource \"{} ({})\"", self.name, self.version)
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum MountType {
    /// Bind mount
    #[serde(rename = "bind")]
    Bind,
    /// A container specific directory created by the runtime in directories.data_dir
    #[serde(rename = "data")]
    Data,
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
pub struct Mount {
    /// Mount source
    pub source: Option<std::path::PathBuf>,
    /// Mount target
    pub target: std::path::PathBuf,
    /// Mount type
    pub r#type: MountType,
    /// Mount flags,
    pub flags: Option<HashSet<MountFlag>>,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct NewBind {
    pub host: std::path::PathBuf,
    pub flags: Option<HashSet<MountFlag>>,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct NewData {
    pub tmpfs: String,
    pub flags: Option<HashSet<MountFlag>>,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct NewResource {
    pub resource: String,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MountSource {
    Bind(NewBind),
    Data(NewData),
    Resource(NewResource),
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize)]
pub struct MountEntry {
    pub target: std::path::PathBuf,
    pub source: MountSource,
}

impl MountEntry {
    pub fn is_resource(&self) -> bool {
        matches!(self.source, MountSource::Resource(_))
    }
}

#[derive(Default, Clone, Eq, PartialEq, Debug, Serialize)]
pub struct MountEntries {
    pub entries: Vec<MountEntry>,
}

impl MountEntries {
    pub fn resources(&self) -> Vec<Resource> {
        self.entries
            .iter()
            .filter(|e| e.is_resource())
            .cloned()
            .filter_map(|e| Resource::try_from(e).ok())
            .collect()
    }

    pub fn mounts(&self) -> Vec<Mount> {
        self.entries
            .iter()
            .filter(|e| !e.is_resource())
            .cloned()
            .filter_map(|e| Mount::try_from(e).ok())
            .collect()
    }
}

/// Serde deserialization for `MountEntries`
impl<'de> Deserialize<'de> for MountEntries {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MountEntriesVisitor;

        impl<'de> Visitor<'de> for MountEntriesVisitor {
            type Value = MountEntries;
            fn visit_map<A>(self, mut map: A) -> Result<MountEntries, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut entries = Vec::new();
                while let Some((target, source)) = map.next_entry()? {
                    entries.push(MountEntry { target, source });
                }
                Ok(MountEntries { entries })
            }

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> ::std::fmt::Result {
                formatter.write_str("mount entry")
            }
        }

        deserializer.deserialize_map(MountEntriesVisitor)
    }
}

impl TryFrom<MountEntry> for Mount {
    type Error = anyhow::Error;
    fn try_from(value: MountEntry) -> Result<Mount> {
        match value.source {
            MountSource::Bind(m) => Ok(Mount {
                source: Some(m.host.clone()),
                target: value.target,
                r#type: MountType::Bind,
                flags: m.flags,
            }),
            MountSource::Data(m) => Ok(Mount {
                source: None,
                target: value.target,
                r#type: MountType::Data,
                flags: m.flags,
            }),
            MountSource::Resource(_) => {
                Err(anyhow!("Can't convert a resource mount entry to a Mount"))
            }
        }
    }
}

impl TryFrom<MountEntry> for Resource {
    type Error = anyhow::Error;
    fn try_from(value: MountEntry) -> Result<Resource> {
        match value.source {
            MountSource::Resource(r) => {
                let re = regex::Regex::new(r"(?P<name>\w+):(?P<version>[\w.]+)(?P<dir>[\w/]+)?")?;
                let caps = re
                    .captures(&r.resource)
                    .ok_or_else(|| anyhow!("Invalid resource: {}", r.resource))?;

                let name = caps
                    .name("name")
                    .map(|m| m.as_str().to_owned())
                    .unwrap_or_default();
                let version: Version =
                    Version::parse(caps.name("version").map(|m| m.as_str()).unwrap_or(""))?;
                let mountpoint = value.target;
                let dir = caps
                    .name("dir")
                    .map(|m| std::path::Path::new(m.as_str()).to_owned())
                    .unwrap_or_else(|| std::path::Path::new("/").to_owned());

                Ok(Resource {
                    name,
                    version,
                    mountpoint,
                    dir,
                })
            }
            MountSource::Bind(_) => Err(anyhow!("Can't convert a bind mount entry to a Resource")),
            MountSource::Data(_) => Err(anyhow!("Can't convert a data mount entry to a Resource")),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Name of container
    pub name: Name,
    /// Container version
    pub version: Version,
    /// Target arch
    pub arch: String,
    /// Path to init
    pub init: Option<std::path::PathBuf>,
    /// Additional arguments for the application invocation
    pub args: Option<Vec<String>>,
    /// Environment passed to container
    pub env: Option<HashMap<String, String>>,
    /// Autostart this container upon north startup
    pub autostart: Option<bool>,
    /// CGroup config
    pub cgroups: Option<CGroups>,
    /// Seccomp configuration
    pub seccomp: Option<HashMap<String, String>>,
    /// Number of instances to mount of this container
    /// The name get's extended with the instance id.
    pub instances: Option<u32>,
    /// List of bind mounts and resources
    pub mounts: Option<MountEntries>,
}

impl Manifest {
    fn verify(&self) -> Result<()> {
        // TODO: check for none on env, autostart, cgroups, seccomp, instances
        if self.init.is_none() && self.args.is_some() {
            return Err(anyhow!("Arguments not allowed in resource container"));
        }
        Ok(())
    }

    pub async fn from_path(f: &Path) -> Result<Manifest> {
        let f = f.to_owned();
        task::spawn_blocking(move || {
            let file = File::open(&f)?;
            let manifest: Manifest = serde_yaml::from_reader(file)
                .with_context(|| format!("Failed to parse manifest from {}", f.display()))?;
            manifest.verify()?;

            Ok(manifest)
        })
        .await
    }
}

impl FromStr for Manifest {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Manifest, Error> {
        let parse_res: std::result::Result<Manifest, Error> =
            serde_yaml::from_str(s).context("Failed to parse manifest");
        if let Ok(manifest) = &parse_res {
            manifest.verify()?;
        }
        parse_res
    }
}

#[async_std::test]
async fn parse() -> Result<()> {
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
    /data:
        tmpfs: size=25
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

    let resources = manifest
        .mounts
        .as_ref()
        .map(|m| m.resources())
        .ok_or_else(|| anyhow!("Missing resource containers"))?;
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].name, "bla".to_owned());
    assert!(manifest.autostart.unwrap());
    let env = manifest.env.ok_or_else(|| anyhow!("Missing env"))?;
    assert_eq!(
        env.get("LD_LIBRARY_PATH"),
        Some("/lib".to_string()).as_ref()
    );
    let mounts = vec![
        Mount {
            source: Some(std::path::PathBuf::from("/lib")),
            target: std::path::PathBuf::from("/lib"),
            r#type: MountType::Bind,
            flags: Some([MountFlag::Rw].iter().cloned().collect()),
        },
        Mount {
            source: None,
            target: std::path::PathBuf::from("/data"),
            r#type: MountType::Data,
            flags: None,
        },
    ];
    let manifest_mounts = manifest
        .mounts
        .as_ref()
        .map(|m| m.mounts())
        .ok_or_else(|| anyhow!("Missing resource containers"))?;
    assert_eq!(manifest_mounts, mounts);
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
