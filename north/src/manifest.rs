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
}

#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub enum MountFlag {
    /// Bind mount
    #[serde(rename = "rw")]
    Rw,
    /// Mount noexec
    #[serde(rename = "noexec")]
    NoExec,
    /// Mount noexec
    #[serde(rename = "nosuid")]
    NoSuid,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Mount {
    /// Mount source
    source: std::path::PathBuf,
    /// Mount target
    target: std::path::PathBuf,
    /// Mount type
    r#type: MountType,
    /// Mount flags,
    flags: Option<HashSet<MountFlag>>,
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
    pub resources: Option<Vec<Resource>>,
    /// Autostart this container upon north startup
    pub autostart: Option<bool>,
    /// Action on application exit
    pub on_exit: Option<OnExit>,
    /// CGroup config
    pub cgroups: Option<CGroups>,
    /// Seccomp configuration
    pub seccomp: Option<HashMap<String, String>>,
    /// Number of instances to mount of this container
    /// The name get's extended with the instance id.
    pub instances: Option<u32>,
    /// Extra mounts
    pub mounts: Option<Vec<Mount>>,
}

impl Manifest {
    fn verify(&self) -> Result<()> {
        if let Some(OnExit::Restart(n)) = self.on_exit {
            if self.init.is_none() {
                return Err(anyhow!(
                    "An `on_exit` tag is not allowed in resource container"
                ));
            }
            if n == 0 {
                return Err(anyhow!("Invalid on_exit value in manifest"));
            }
        }
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
args: [one, two]
env:
    LD_LIBRARY_PATH: /lib
mounts:
    - source: /lib
      target: /lib
      type: bind
      flags: 
        - rw
        - noexec
        - nosuid
resources:
    - name: bla
      version: 1.0.0
      dir: /bin/foo
      mountpoint: /here/we/go
autostart: true
on_exit:
    restart: 3
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
        .resources
        .ok_or_else(|| anyhow!("Missing resource containers"))?;
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].name, "bla".to_owned());
    assert!(manifest.autostart.unwrap());
    assert_eq!(manifest.on_exit, Some(OnExit::Restart(3)));
    let env = manifest.env.ok_or_else(|| anyhow!("Missing env"))?;
    assert_eq!(
        env.get("LD_LIBRARY_PATH"),
        Some("/lib".to_string()).as_ref()
    );
    let mount = Mount {
        source: std::path::PathBuf::from("/lib"),
        target: std::path::PathBuf::from("/lib"),
        r#type: MountType::Bind,
        flags: Some(
            [MountFlag::Rw, MountFlag::NoExec, MountFlag::NoSuid]
                .iter()
                .cloned()
                .collect(),
        ),
    };
    assert_eq!(manifest.mounts.unwrap(), vec!(mount));
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

#[async_std::test]
async fn parse_invalid_on_exit() -> std::io::Result<()> {
    use async_std::path::PathBuf;
    use std::{fs::File, io::Write};

    let file = tempfile::NamedTempFile::new()?;
    let path = file.path();

    let m = "
name: hello
version: 0.0.0
arch: aarch64-linux-android
init: /binary
args: [one, two]
env:
    LD_LIBRARY_PATH: /lib
on_exit:
    Restart: 0
";

    let mut file = File::create(path)?;
    file.write_all(m.as_bytes())?;
    drop(file);

    let manifest = Manifest::from_path(&PathBuf::from(path)).await;
    assert!(manifest.is_err());
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
