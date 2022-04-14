use itertools::Itertools;
use schemars::JsonSchema;
use serde::{
    de::{Deserializer, Visitor},
    ser::SerializeSeq,
    Deserialize, Serialize, Serializer,
};
use std::{collections::HashSet, fmt};
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{EnumCount, EnumIter};

/// Console features. Matches the api request struct and notifications
#[derive(
    Clone, Eq, EnumIter, EnumCount, PartialEq, Debug, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Shutdown the runtime
    Shutdown,
    /// List containers
    Containers,
    /// List repositories
    Repositories,
    /// Start a container
    Start,
    /// Send a singal to a container
    Kill,
    /// Install a container
    Install,
    /// Mount a container
    Mount,
    /// Umount a container
    Umount,
    /// Uninstall a container
    Uninstall,
    /// Collect container resource statistics
    ContainerStatistics,
    /// Notifications
    Notifications,
    /// Token creation and verification
    Token,
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_plain::to_string(self).unwrap())
    }
}

/// Console access level: list of allowed request message types
/// ```yaml
/// console:
///   - shutdown
///   - start
/// ```
/// or
/// ```yaml
/// console: full
/// ```
#[derive(Default, Clone, Eq, PartialEq, Debug, JsonSchema)]
pub struct Console {
    /// List of features
    permissions: HashSet<Permission>,
}

impl Console {
    /// Create a new `Console` with all permissions given
    pub fn full() -> Console {
        let permissions = HashSet::from_iter(Permission::iter());
        Console { permissions }
    }
}

impl std::ops::Deref for Console {
    type Target = HashSet<Permission>;

    fn deref(&self) -> &Self::Target {
        &self.permissions
    }
}

impl fmt::Display for Console {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.permissions.len() == Permission::COUNT {
            write!(f, "full")
        } else {
            let permissions = self.permissions.iter().format(", ");
            write!(f, "{}", permissions)
        }
    }
}

impl<'de> Deserialize<'de> for Console {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PermissionVisitor;
        impl<'de> Visitor<'de> for PermissionVisitor {
            type Value = Console;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("\"full\" or a permission sequence")
            }

            fn visit_str<E: serde::de::Error>(self, str_data: &str) -> Result<Console, E> {
                match str_data.trim() {
                    "full" => Ok(Console {
                        permissions: HashSet::from_iter(Permission::iter()),
                    }),
                    _ => Err(serde::de::Error::custom(format!(
                        "invalid console permission: {}",
                        str_data
                    ))),
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Console, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut permissions = HashSet::new();
                while let Some(permission) = seq.next_element()? {
                    permissions.insert(permission);
                }
                Ok(Console { permissions })
            }
        }

        deserializer.deserialize_any(PermissionVisitor)
    }
}

impl Serialize for Console {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.permissions.len() == Permission::COUNT {
            serializer.serialize_str("full")
        } else {
            let mut seq = serializer.serialize_seq(Some(self.permissions.len()))?;
            for e in self.permissions.iter() {
                seq.serialize_element(e)?;
            }
            seq.end()
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::{super::Manifest, *};
    use anyhow::Result;

    /// Full console access
    #[test]
    fn full() -> Result<()> {
        let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
console: full
";
        let manifest = Manifest::from_str(manifest).expect("failed to parse");
        for permission in Permission::iter() {
            assert!(manifest.console.contains(&permission));
        }
        Ok(())
    }

    /// No console permissions
    #[test]
    fn none() -> Result<()> {
        let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001";
        let manifest = Manifest::from_str(manifest).expect("failed to parse");
        assert!(manifest.console.is_empty());
        Ok(())
    }

    /// List of console permissions
    #[test]
    fn list() -> Result<()> {
        let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
console:
  - shutdown
  - start
";
        let manifest = Manifest::from_str(manifest).expect("failed to parse");
        assert!(manifest.console.len() == 2);
        Ok(())
    }
}
