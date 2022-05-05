use itertools::Itertools;
use schemars::JsonSchema;
use serde::{
    de::{Deserializer, Visitor},
    ser::SerializeSeq,
    Deserialize, Serialize, Serializer,
};
use serde_with::skip_serializing_none;
use std::{collections::HashSet, fmt};
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{EnumCount, EnumIter};

/// Console Quality of Service
#[skip_serializing_none]
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsoleConfiguration {
    /// Permissions
    pub permissions: Permissions,
    /// Limits the number of requests processed per second
    pub max_requests_per_sec: Option<u32>,
}

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
    /// Identification
    Ident,
}

#[allow(clippy::unwrap_used)]
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
pub struct Permissions(HashSet<Permission>);

impl Permissions {
    /// Create a new `Console` with all permissions given
    pub fn full() -> Permissions {
        Permissions(HashSet::from_iter(Permission::iter()))
    }
}

impl std::ops::Deref for Permissions {
    type Target = HashSet<Permission>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.len() == Permission::COUNT {
            write!(f, "full")
        } else {
            let permissions = self.0.iter().format(", ");
            write!(f, "{}", permissions)
        }
    }
}

impl<'de> Deserialize<'de> for Permissions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PermissionVisitor;
        impl<'de> Visitor<'de> for PermissionVisitor {
            type Value = Permissions;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("\"full\" or a permission sequence")
            }

            fn visit_str<E: serde::de::Error>(self, str_data: &str) -> Result<Permissions, E> {
                match str_data.trim() {
                    "full" => Ok(Permissions(HashSet::from_iter(Permission::iter()))),
                    _ => Err(serde::de::Error::custom(format!(
                        "invalid console permission: {}",
                        str_data
                    ))),
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Permissions, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut permissions = HashSet::new();
                while let Some(permission) = seq.next_element()? {
                    permissions.insert(permission);
                }
                Ok(Permissions(permissions))
            }
        }

        deserializer.deserialize_any(PermissionVisitor)
    }
}

impl Serialize for Permissions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.0.len() == Permission::COUNT {
            serializer.serialize_str("full")
        } else {
            let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
            for e in self.0.iter() {
                seq.serialize_element(e)?;
            }
            seq.end()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::str::FromStr;

    use super::{super::Manifest, *};
    use anyhow::Result;

    /// Full console access
    #[test]
    fn full() -> Result<()> {
        let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
console:
    permissions: full
";
        let manifest = Manifest::from_str(manifest).expect("failed to parse");
        for permission in Permission::iter() {
            let console = manifest.console.as_ref().unwrap();
            assert!(console.permissions.contains(&permission));
        }
        Ok(())
    }

    /// No console permissions
    #[test]
    fn none() -> Result<()> {
        let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001";
        let manifest = Manifest::from_str(manifest).expect("failed to parse");
        assert!(manifest.console.is_none());
        Ok(())
    }

    /// List of console permissions
    #[test]
    fn list() -> Result<()> {
        let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
console:
  permissions:
    - shutdown
    - start
";
        let manifest = Manifest::from_str(manifest).expect("failed to parse");
        let console = manifest.console.as_ref().unwrap();
        assert!(console.permissions.len() == 2);
        Ok(())
    }
}
