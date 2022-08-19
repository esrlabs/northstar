use crate::{
    common::non_nul_string::NonNulString,
    seccomp::{Seccomp, SyscallRule},
};
use itertools::Itertools;
use std::{
    collections::{HashMap, HashSet},
    path::{Component, Component::RootDir, Path},
};
use validator::ValidationError;

use super::{
    mount::{Mount, MountOption, MountPoint},
    selinux::Selinux,
    Manifest,
};

/// Max length of init in characters
const MAX_LENGTH_INIT: usize = 4096;
/// Maximum number of environment variables
const MAX_ENV_VARS: usize = 64;
/// Maximum length of a environment variable name
const MAX_ENV_VAR_NAME_LENGTH: usize = 64;
/// Maximum length of a environment variable value
const MAX_ENV_VAR_VALUE_LENTH: usize = 1024;
/// Maximum number of supplementary groups
const MAX_SUPPL_GROUPS: usize = 64;
/// Max length of a supplementary group name
const MAX_SUPPL_GROUP_LENGTH: usize = 64;
/// Max length of a network namespace
const MAX_NET_NAMESPACE_LENGTH: usize = 256;

/// Environment varibables used by the runtime and not available to the user.
const RESERVED_ENV_VARIABLES: &[&str] = &[
    "NORTHSTAR_NAME",
    "NORTHSTAR_VERSION",
    "NORTHSTAR_CONTAINER",
    "NORTHSTAR_CONSOLE",
];

pub fn manifest(manifest: &Manifest) -> Result<(), ValidationError> {
    // Most optionals in the manifest are not valid for a resource container
    if manifest.init.is_none()
        && (!manifest.args.is_empty()
            || !manifest.capabilities.is_empty()
            || !manifest.env.is_empty()
            || !manifest.suppl_groups.is_empty()
            || manifest.autostart.is_some()
            || manifest.cgroups.is_some()
            || manifest.io.is_some()
            || manifest.seccomp.is_some())
    {
        return Err(ValidationError::new(
            "resource containers must not define any of the following manifest entries:\
                args, env, autostart, cgroups, seccomp, capabilities, suppl_groups, io",
        ));
    }

    Ok(())
}

/// Validate the map of environment variables. They shall not contain reserved variable names
/// that are used by the runtime.
pub fn init(init: &NonNulString) -> Result<(), ValidationError> {
    if init.len() > MAX_LENGTH_INIT {
        Err(ValidationError::new("init exceeds max length"))
    } else {
        Ok(())
    }
}

/// Validate the map of environment variables. They shall not contain reserved variable names
/// that are used by the runtime.
pub fn env(env: &HashMap<NonNulString, NonNulString>) -> Result<(), ValidationError> {
    // Check the number of env variables
    if env.len() > MAX_ENV_VARS {
        return Err(ValidationError::new("env exceeds max length"));
    }

    // Check the lenght of each env variable name
    if env.keys().any(|k| k.len() > MAX_ENV_VAR_NAME_LENGTH) {
        return Err(ValidationError::new("env variable name exceeds max length"));
    }

    // Check the lenght of each env variable value
    if env.values().any(|v| v.len() > MAX_ENV_VAR_VALUE_LENTH) {
        return Err(ValidationError::new("env value exceeds max length"));
    }

    // Check for reserved env variable names
    if RESERVED_ENV_VARIABLES.iter().any(|key| {
        env.contains_key(unsafe { &NonNulString::from_str_unchecked(key) }) // safe - constants
    }) {
        Err(ValidationError::new("reserved env variable name"))
    } else {
        Ok(())
    }
}

pub fn mounts(mounts: &HashMap<MountPoint, Mount>) -> Result<(), ValidationError> {
    // Check for relative and overlapping bind mounts
    let mut prev_comps = vec![RootDir];
    mounts
        .iter()
        .filter(|(_, m)| matches!(m, Mount::Bind(_)))
        .map(|(p, _)| p)
        .sorted()
        .try_for_each(|p| {
            let p: &Path = p.as_ref();
            if p.is_relative() {
                return Err(ValidationError::new("mount points must not be relative"));
            }
            // Check for overlapping bind mount paths by checking if one path is the prefix of the next one
            let curr_comps: Vec<Component> = p.components().into_iter().collect();
            let prev_too_short = prev_comps.len() <= 1; // Two mount paths both starting with '/' is not considered an overlap
            let prev_too_long = prev_comps.len() > curr_comps.len(); // A longer path cannot be the prefix of a shorter one

            if !prev_too_short && !prev_too_long && prev_comps == curr_comps[..prev_comps.len()] {
                Err(ValidationError::new("mount points must not overlap"))
            } else {
                prev_comps = curr_comps;
                Ok(())
            }
        })?;

    // Check for recursive non bind mounts
    mounts.iter().map(|(_, m)| m).try_for_each(|m| match m {
        // Recursive bind mounts are allowed but not resources
        Mount::Resource(m) if m.options.contains(&MountOption::Rec) => Err(ValidationError::new(
            "non bind mounts must not be recursive",
        )),
        Mount::Resource(m) if !m.dir.starts_with('/') => Err(ValidationError::new(
            "resource directory options must not be absolute",
        )),
        _ => Ok(()),
    })
}

/// Validate selinux settings
pub fn selinux(selinux: &Selinux) -> Result<(), ValidationError> {
    // Maximum length since at least Linux v3.7
    // (https://elixir.bootlin.com/linux/v3.7/source/include/uapi/linux/limits.h)
    const XATTR_SIZE_MAX: usize = 65536;

    if selinux.context.len() >= XATTR_SIZE_MAX {
        return Err(ValidationError::new("Selinux context too long"));
    }

    if !selinux
        .context
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '_')
    {
        return Err(ValidationError::new(
            "Selinux context must consist of alphanumeric ASCII characters, '?' or '_'",
        ));
    }

    Ok(())
}

/// Validate seccomp rules
pub fn seccomp(seccomp: &Seccomp) -> Result<(), ValidationError> {
    // Check seccomp filter
    const MAX_ARG_INDEX: usize = 5; // Restricted by seccomp_data struct
    const MAX_ARG_VALUES: usize = 50; // BPF jumps cannot exceed 255 and each check needs multiple instructions
    if let Some(allowlist) = &seccomp.allow {
        for filter in allowlist {
            match filter.1 {
                SyscallRule::Args(args) => {
                    if args.index > MAX_ARG_INDEX {
                        return Err(ValidationError::new(
                            "Seccomp syscall argument index must be MAX_ARG_INDEX or less",
                        ));
                    }
                    if args.values.is_none() && args.mask.is_none() {
                        return Err(ValidationError::new(
                                    "Either 'values' or 'mask' must be defined in seccomp syscall argument filter"));
                    }
                    if let Some(values) = &args.values {
                        if values.len() > MAX_ARG_VALUES {
                            return Err(ValidationError::new(
                                "Seccomp syscall argument cannot have more than MAX_ARG_VALUES allowed values",
                            ));
                        }
                    }
                }
                SyscallRule::Any => {
                    // This syscall is allowed unconditionally
                }
            }
        }
    }
    Ok(())
}

/// Validate supplementary groups for number and length
pub fn suppl_groups(groups: &HashSet<NonNulString>) -> Result<(), ValidationError> {
    if groups.len() > MAX_SUPPL_GROUPS {
        return Err(ValidationError::new(
            "supplementary groups exceeds max length",
        ));
    }

    if groups.iter().any(|g| g.len() > MAX_SUPPL_GROUP_LENGTH) {
        return Err(ValidationError::new(
            "supplementary group name exceeds max length",
        ));
    }
    Ok(())
}

/// Validate network namespace setting
pub fn netns(netns: &NonNulString) -> Result<(), ValidationError> {
    if netns.len() > MAX_NET_NAMESPACE_LENGTH {
        Err(ValidationError::new("network namespace exceeds max length"))
    } else {
        Ok(())
    }
}
