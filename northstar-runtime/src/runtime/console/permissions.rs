use heck::ToSnakeCase;
use itertools::Itertools;
use std::{collections::HashSet, fmt};

use crate::npk::manifest::console::{
    Permission as ManifestPermission, Permissions as ManifestPermissions,
};

/// Set of permissions.
#[derive(Debug, Clone)]
pub struct Permissions(HashSet<Permission>);

impl Permissions {
    /// Returns true if permission is set.
    pub fn contains(&self, permission: &Permission) -> bool {
        self.0.contains(permission)
    }
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.iter().sorted().format(", "))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum Permission {
    /// Identification
    Ident,
    /// Inspect a container
    Inspect,
    /// Install a container
    Install,
    /// Send a singal to a container
    Kill,
    /// List all containers
    List,
    /// Notifications
    Notifications,
    /// Mount a container
    Mount,
    /// List repositories
    Repositories,
    /// Shutdown the runtime
    Shutdown,
    /// Start a container
    Start,
    /// Start a container with extra args and env
    StartWithArgsAndEnv,
    /// Token creation
    TokenCreate,
    /// Token verification
    TokenVerification,
    /// Umount a container
    Umount,
    /// Uninstall a container
    Uninstall,
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        let s = format!("{:?}", self).to_snake_case();
        write!(f, "{}", s)
    }
}

impl From<crate::npk::manifest::console::Permissions> for Permissions {
    fn from(permissions: ManifestPermissions) -> Self {
        Permissions(permissions.iter().cloned().map(Into::into).collect())
    }
}

impl From<crate::npk::manifest::console::Permission> for Permission {
    fn from(permission: ManifestPermission) -> Permission {
        match permission {
            ManifestPermission::Ident => Permission::Ident,
            ManifestPermission::Inspect => Permission::Inspect,
            ManifestPermission::Install => Permission::Install,
            ManifestPermission::Kill => Permission::Kill,
            ManifestPermission::List => Permission::List,
            ManifestPermission::Notifications => Permission::Notifications,
            ManifestPermission::Mount => Permission::Mount,
            ManifestPermission::Repositories => Permission::Repositories,
            ManifestPermission::Shutdown => Permission::Shutdown,
            ManifestPermission::Start => Permission::Start,
            ManifestPermission::StartWithArgsAndEnv => Permission::StartWithArgsAndEnv,
            ManifestPermission::TokenCreate => Permission::TokenCreate,
            ManifestPermission::TokenVerification => Permission::TokenVerification,
            ManifestPermission::Umount => Permission::Umount,
            ManifestPermission::Uninstall => Permission::Uninstall,
        }
    }
}
