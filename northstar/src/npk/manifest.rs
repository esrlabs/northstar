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

use crate::common::{name::Name, non_null_string::NonNullString, version::Version};
use itertools::Itertools;
use serde::{
    de::{Deserializer, Visitor},
    Deserialize, Serialize,
};
use serde_with::skip_serializing_none;
use serde_yaml::Value;
use std::{
    collections::{HashMap, HashSet},
    fmt, io,
    path::{Component, Component::RootDir, PathBuf},
    str::FromStr,
};
use thiserror::Error;

pub type Capability = caps::Capability;
pub type CGroupConfig = HashMap<NonNullString, NonNullString>;
pub type CGroups = HashMap<NonNullString, CGroupConfig>;
pub type MountOptions = HashSet<MountOption>;

#[skip_serializing_none]
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Name of container
    pub name: Name,
    /// Container version
    pub version: Version,
    /// Path to init
    pub init: Option<PathBuf>,
    /// Additional arguments for the application invocation
    pub args: Option<Vec<NonNullString>>,
    /// UID
    pub uid: u16,
    /// GID
    pub gid: u16,
    /// Environment passed to container
    pub env: Option<HashMap<NonNullString, NonNullString>>,
    /// Autostart this container upon northstar startup
    pub autostart: Option<Autostart>,
    /// CGroup config
    pub cgroups: Option<CGroups>,
    /// Seccomp configuration
    pub seccomp: Option<Seccomp>,
    /// List of bind mounts and resources
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        with = "::serde_with::rust::maps_duplicate_key_is_error"
    )]
    pub mounts: HashMap<PathBuf, Mount>,
    /// String containing capability names to give to
    /// new container
    #[serde(default, with = "serde_caps")]
    pub capabilities: Option<HashSet<Capability>>,
    /// String containing group names to give to new container
    pub suppl_groups: Option<Vec<NonNullString>>,
    /// IO configuration
    pub io: Option<Io>,
    /// Optional custom data. The runtime doesnt use this.
    pub custom: Option<Value>,
}

impl Manifest {
    /// Manifest version supported by the runtime
    pub const VERSION: Version = Version {
        major: 0,
        minor: 1,
        patch: 0,
        pre: vec![],
        build: vec![],
    };

    pub fn from_reader<R: io::Read>(reader: R) -> Result<Self, Error> {
        let manifest: Self = serde_yaml::from_reader(reader).map_err(Error::SerdeYaml)?;
        manifest.verify()?;
        Ok(manifest)
    }

    pub fn to_writer<W: io::Write>(&self, writer: W) -> Result<(), Error> {
        serde_yaml::to_writer(writer, self).map_err(Error::SerdeYaml)
    }

    fn verify(&self) -> Result<(), Error> {
        // Most optionals in the manifest are not valid for a resource container
        if self.init.is_none()
            && (self.args.is_some()
                || self.env.is_some()
                || self.autostart.is_some()
                || self.cgroups.is_some()
                || self.seccomp.is_some()
                || self.capabilities.is_some()
                || self.suppl_groups.is_some()
                || self.io.is_some())
        {
            return Err(Error::Invalid(
                "Resource containers must not define any of the following manifest entries:\
                args, env, autostart, cgroups, seccomp, capabilities, suppl_groups, io"
                    .to_string(),
            ));
        }

        // Check for invalid uid or gid of 0
        if self.uid == 0 {
            return Err(Error::Invalid("Invalid uid of 0".to_string()));
        }
        if self.gid == 0 {
            return Err(Error::Invalid("Invalid gid of 0".to_string()));
        }

        // Check for relative and overlapping bind mounts
        let mut prev_comps = vec![RootDir];
        self.mounts
            .iter()
            .filter(|(_, m)| matches!(m, Mount::Bind(_)))
            .map(|(p, _)| p)
            .sorted()
            .try_for_each(|p| {
                if p.is_relative() {
                    return Err(Error::Invalid(
                        "Mount points must not be relative".to_string(),
                    ));
                }
                // Check for overlapping bind mount paths by checking if one path is the prefix of the next one
                let curr_comps: Vec<Component> = p.components().into_iter().collect();
                let prev_too_short = prev_comps.len() <= 1; // Two mount paths both starting with '/' is not considered an overlap
                let prev_too_long = prev_comps.len() > curr_comps.len(); // A longer path cannot be the prefix of a shorter one

                if !prev_too_short && !prev_too_long && prev_comps == curr_comps[..prev_comps.len()]
                {
                    return Err(Error::Invalid("Mount points must not overlap".to_string()));
                }
                prev_comps = curr_comps;
                Ok(())
            })?;
        Ok(())
    }
}

impl FromStr for Manifest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Manifest, Error> {
        let manifest: Self = serde_yaml::from_str(s).map_err(Error::SerdeYaml)?;
        manifest.verify()?;
        Ok(manifest)
    }
}

impl ToString for Manifest {
    fn to_string(&self) -> String {
        // A `Manifest` is convertible to `String` as long as its implementation of `Serialize` does
        // not return an error. This should never happen for the types that we use in `Manifest` so
        // we can safely use .unwrap() here.
        serde_yaml::to_string(self).unwrap()
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid manifest: {0}")]
    Invalid(String),
    #[error("Failed to parse: {0}")]
    SerdeYaml(#[from] serde_yaml::Error),
}

/// Autostart options
#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub enum Autostart {
    /// Ignore errors when starting this container. Ignore the containers termination result
    #[serde(rename = "relaxed")]
    Relaxed,
    /// Exit the runtime if starting this containers fails or the container exits with a non zero exit code.
    /// Use this variant to propagate errors with a container to the system above the runtime e.g init.
    #[serde(rename = "critical")]
    Critical,
}

#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
/// Mount options
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
}

/// Resource mount configuration
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub name: Name,
    pub version: Version,
    pub dir: PathBuf,
    #[serde(
        default,
        with = "mount_options",
        skip_serializing_if = "HashSet::is_empty"
    )]
    pub options: MountOptions,
}

/// Bind mount configuration
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bind {
    pub host: PathBuf,
    #[serde(
        default,
        with = "mount_options",
        skip_serializing_if = "HashSet::is_empty"
    )]
    pub options: MountOptions,
}

/// Tmpfs configuration
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Tmpfs {
    #[serde(deserialize_with = "deserialize_tmpfs_size")]
    pub size: u64,
}

/// Mounts
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Mount {
    /// Bind mount of a host dir with options
    #[serde(rename = "bind")]
    Bind(Bind),
    /// Mount /dev with flavor `dev`
    #[serde(rename = "dev")]
    Dev,
    /// Mount a rw host directory dedicated to this container rw
    #[serde(rename = "persist")]
    Persist,
    /// Mount a directory from a resource
    #[serde(rename = "resource")]
    Resource(Resource),
    /// Mount a tmpfs with size
    #[serde(rename = "tmpfs")]
    Tmpfs(Tmpfs),
}

/// Pre-defined seccomp profiles
#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub enum Profile {
    /// Default seccomp filter similar to docker's default profile
    #[serde(rename = "default")]
    Default,
}

/// Seccomp configuration
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seccomp {
    /// Pre-defined seccomp profile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    /// Explicit list of allowed syscalls
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<HashSet<String>>,
}

/// IO configuration for stdin, stdout, stderr
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Io {
    /// stdout configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<Output>,
    /// stderr configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<Output>,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Output {
    /// Inherit the runtimes stdout/stderr
    #[serde(rename = "pipe")]
    Pipe,
    /// Forward output to the logging system with level and optional tag
    #[serde(rename = "log")]
    Log { level: log::Level, tag: String },
}

mod mount_options {
    use super::{MountOption, MountOptions};
    use itertools::Itertools;
    use serde::{de::Visitor, Deserializer, Serializer};
    use std::str::FromStr;

    impl ToString for MountOption {
        fn to_string(&self) -> String {
            match self {
                MountOption::Rw => "rw",
                MountOption::NoExec => "noexec",
                MountOption::NoSuid => "nosuid",
                MountOption::NoDev => "nodev",
            }
            .to_string()
        }
    }

    impl FromStr for MountOption {
        type Err = String;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "rw" => Ok(MountOption::Rw),
                "noexec" => Ok(MountOption::NoExec),
                "nosuid" => Ok(MountOption::NoSuid),
                "nodev" => Ok(MountOption::NoDev),
                _ => Err(format!("invalid mount option {}", s)),
            }
        }
    }

    pub(super) fn serialize<S: Serializer>(
        options: &MountOptions,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&options.iter().map(ToString::to_string).join(","))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<MountOptions, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MountOptionsVisitor;
        impl<'de> Visitor<'de> for MountOptionsVisitor {
            type Value = MountOptions;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> ::std::fmt::Result {
                formatter.write_str("comma seperated mount options")
            }

            fn visit_str<E: serde::de::Error>(self, str_data: &str) -> Result<MountOptions, E> {
                let options = str_data.trim();
                if !options.is_empty() {
                    let iter = options.split(',');
                    let mut result = MountOptions::with_capacity(iter.size_hint().0);
                    for opt in iter {
                        result.insert(
                            MountOption::from_str(opt.trim()).map_err(serde::de::Error::custom)?,
                        );
                    }
                    Ok(result)
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

mod serde_caps {
    use super::Capability;
    use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serializer};
    use std::{collections::HashSet, str::FromStr};

    pub(super) fn serialize<S: Serializer>(
        caps: &Option<HashSet<Capability>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if let Some(caps) = caps {
            let mut seq = serializer.serialize_seq(Some(caps.len()))?;
            for cap in caps {
                seq.serialize_element(&cap.to_string())?;
            }
            seq.end()
        } else {
            serializer.serialize_none()
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<HashSet<Capability>>, D::Error> {
        let s: Option<HashSet<String>> = Option::deserialize(deserializer)?;
        if let Some(s) = s {
            if s.is_empty() {
                Ok(None)
            } else {
                let mut result = HashSet::with_capacity(s.len());
                for cap in s {
                    let cap = Capability::from_str(&cap).map_err(serde::de::Error::custom)?;
                    result.insert(cap);
                }
                Ok(Some(result))
            }
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::npk::manifest::*;
    use anyhow::{anyhow, Result};
    use std::{
        convert::{TryFrom, TryInto},
        iter::FromIterator,
    };

    #[test]
    fn parse() -> Result<()> {
        let manifest = "
name: hello
version: 0.0.0
init: /binary
args:
  - one
  - two
env:
  LD_LIBRARY_PATH: /lib
uid: 1000
gid: 1001
suppl_groups:
  - inet
  - log
capabilities:
  - CAP_NET_RAW
  - CAP_MKNOD
  - CAP_SYS_TIME
mounts:
  /dev:
    type: dev
  /tmp:
    type: tmpfs
    size: 42
  /lib:
    type: bind
    host: /lib
    options: rw
  /data:
    type: persist
  /resource:
    type: resource
    name: bla-blah.foo
    version: 1.0.0
    dir: /bin/foo
    options: noexec
autostart: critical
cgroups:
  memory:
    limit_in_bytes: 30
  cpu:
    shares: 100
seccomp:
  allowlist: [
    fork,
    waitpid
  ]
";

        let manifest = Manifest::from_str(&manifest)?;

        assert_eq!(manifest.init, Some(PathBuf::from("/binary")));
        assert_eq!(manifest.name.to_string(), "hello");
        let args = manifest.args.ok_or_else(|| anyhow!("Missing args"))?;
        assert_eq!(args.len(), 2);
        assert_eq!(args[0].to_string(), "one");
        assert_eq!(args[1].to_string(), "two");

        assert_eq!(manifest.autostart, Some(Autostart::Critical));
        let env = manifest.env.ok_or_else(|| anyhow!("Missing env"))?;
        assert_eq!(
            env.get(&"LD_LIBRARY_PATH".try_into()?),
            Some("/lib".try_into()?).as_ref()
        );
        assert_eq!(manifest.uid, 1000);
        assert_eq!(manifest.gid, 1001);
        let mut mounts = HashMap::new();
        mounts.insert(
            PathBuf::from("/lib"),
            Mount::Bind(Bind {
                host: PathBuf::from("/lib"),
                options: [MountOption::Rw].iter().cloned().collect(),
            }),
        );
        mounts.insert(PathBuf::from("/data"), Mount::Persist);
        mounts.insert(
            PathBuf::from("/resource"),
            Mount::Resource(Resource {
                name: "bla-blah.foo".try_into()?,
                version: Version::parse("1.0.0")?,
                dir: PathBuf::from("/bin/foo"),
                options: [MountOption::NoExec].iter().cloned().collect(),
            }),
        );
        mounts.insert(PathBuf::from("/tmp"), Mount::Tmpfs(Tmpfs { size: 42 }));
        mounts.insert(PathBuf::from("/dev"), Mount::Dev);
        assert_eq!(manifest.mounts, mounts);

        let mut cgroups = HashMap::new();
        let mut mem = HashMap::new();
        let mut cpu = HashMap::new();
        mem.insert("limit_in_bytes".try_into()?, "30".try_into()?);
        cpu.insert("shares".try_into()?, "100".try_into()?);
        cgroups.insert("memory".try_into()?, mem);
        cgroups.insert("cpu".try_into()?, cpu);

        assert_eq!(manifest.cgroups, Some(cgroups));

        let mut seccomp = HashSet::new();
        seccomp.insert("fork".to_string());
        seccomp.insert("waitpid".to_string());
        assert_eq!(
            manifest.seccomp,
            Some(Seccomp {
                profile: None,
                allowlist: Some(seccomp)
            })
        );

        assert_eq!(
            manifest.capabilities,
            Some(HashSet::from_iter(
                vec!(
                    caps::Capability::CAP_NET_RAW,
                    caps::Capability::CAP_MKNOD,
                    caps::Capability::CAP_SYS_TIME,
                )
                .drain(..)
            ))
        );
        assert_eq!(
            manifest.suppl_groups,
            Some(vec!("inet".try_into()?, "log".try_into()?))
        );

        Ok(())
    }

    /// Two mounts on the same target are invalid
    #[test]
    fn duplicate_mount() -> Result<()> {
        let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
mounts:
  /dev:
    type: dev
  /dev:
    type: dev
";
        assert!(Manifest::from_str(manifest).is_err());
        Ok(())
    }

    /// Overlapping mounts are invalid
    #[test]
    fn overlapping_mount() -> Result<()> {
        let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
mounts:
  /lib/overlapping:
    type: bind
    host: /lib
  /lib/non_overlapping1:
    type: bind
    host: /lib
  /lib/non_overlapping2:
    type: bind
    host: /lib
  /lib/overlapping:
    type: bind
    host: /lib
";
        assert!(Manifest::from_str(manifest).is_err());
        Ok(())
    }

    /// Non-overlapping mounts are invalid
    #[test]
    fn non_overlapping_mount() -> Result<()> {
        let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
mounts:
  /other_lib1:
    type: bind
    host: /lib
  /lib/non_overlapping1:
    type: bind
    host: /lib
  /other_lib2:
    type: bind
    host: /lib
  /lib/non_overlapping2:
    type: bind
    host: /lib
";
        assert!(Manifest::from_str(manifest).is_ok());
        Ok(())
    }

    #[test]
    fn tmpfs() {
        let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
mounts:
  /a:
    type: tmpfs
    size: 100
  /b:
    type: tmpfs
    size: 100kB
  /c:
    type: tmpfs
    size: 100MB
  /d:
    type: tmpfs
    size: 100GB
";
        let manifest = Manifest::from_str(manifest).unwrap();
        assert_eq!(
            manifest.mounts.get(&PathBuf::from("/a")),
            Some(&Mount::Tmpfs(Tmpfs { size: 100 }))
        );
        assert_eq!(
            manifest.mounts.get(&PathBuf::from("/b")),
            Some(&Mount::Tmpfs(Tmpfs { size: 100000 }))
        );
        assert_eq!(
            manifest.mounts.get(&PathBuf::from("/c")),
            Some(&Mount::Tmpfs(Tmpfs { size: 100000000 }))
        );
        assert_eq!(
            manifest.mounts.get(&PathBuf::from("/d")),
            Some(&Mount::Tmpfs(Tmpfs { size: 100000000000 }))
        );

        // Test a invalid tmpfs size string
        let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\n uid: 1000\ngid: 1001
mounts:
  /tmp:
    type: tmpfs
    size: 100MB
";
        assert!(Manifest::from_str(manifest).is_err());
    }

    #[test]
    fn dev_minimal() {
        let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001\nmounts:\n  /dev:\n    type: dev";
        assert!(Manifest::from_str(manifest).is_ok());
    }

    #[test]
    fn mount_resource() {
        let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
mounts:
  /foo:
    type: resource
    name: foo-bar.qwerty12
    version: 0.0.1
    dir: /
    options: rw,noexec,nosuid
";
        Manifest::from_str(manifest).unwrap();
    }

    #[test]
    fn roundtrip() -> Result<()> {
        let m = "
name: hello
version: 0.0.0
init: /binary
uid: 1000
gid: 1001
args:
  - one
  - two
env:
  LD_LIBRARY_PATH: /lib
mounts:
  /dev:
    type: dev
  /lib:
    type: bind
    host: /lib
    options: rw,nosuid,nodev,noexec
  /no_option:
    type: bind
    host: /foo
  /data:
    type: persist
  /resource:
    type: resource
    name: bla-bar.blah1234
    version: 1.0.0
    dir: /bin/foo
    options: rw,nosuid,nodev,noexec
  /tmp:
    type: tmpfs
    size: 42
autostart: relaxed
cgroups:
  memory:
    limit_in_bytes: 30
  cpu:
    shares: 100
seccomp:
  allowlist: [
    fork,
    waitpid
  ]
capabilities:
  - CAP_NET_ADMIN
io:
  stdout: 
    log:
      level: DEBUG
      tag: test
  stderr: pipe
custom:
    blah: foo
    foo: 234
    test:
      - one
      - two
      - three
";

        let manifest = serde_yaml::from_str::<Manifest>(m)?;
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

    #[test]
    fn valid_container_name() -> Result<()> {
        assert!(Name::try_from("test-container-name.valid").is_ok());
        Ok(())
    }

    #[test]
    fn invalid_container_name() -> Result<()> {
        assert!(Name::try_from("test+invalid").is_err());
        Ok(())
    }

    #[test]
    fn valid_non_null_string() -> Result<()> {
        assert!(NonNullString::try_from("test_non_null.string").is_ok());
        Ok(())
    }

    #[test]
    fn invalid_non_null_string() -> Result<()> {
        assert!(NonNullString::try_from("test_null\0.string").is_err());
        Ok(())
    }
}
