use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

use crate::common::non_nul_string::NonNulString;

/// SELinux configuration
#[derive(Clone, Eq, PartialEq, Debug, Validate, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selinux {
    /// Default SE label (mount option context=...).
    #[validate(custom = "validate_context")]
    pub mount_context: Option<NonNulString>,
    /// SE context for the execve call from init.
    #[validate(custom = "validate_context")]
    pub exec: Option<NonNulString>,
}

/// Validate selinux settings
fn validate_context<T: AsRef<str>>(context: T) -> Result<(), ValidationError> {
    // Maximum length since at least Linux v3.7
    // (https://elixir.bootlin.com/linux/v3.7/source/include/uapi/linux/limits.h)
    const XATTR_SIZE_MAX: usize = 65536;

    if context.as_ref().is_empty() {
        return Err(ValidationError::new("SELinux context is empty"));
    }

    if context.as_ref().len() >= XATTR_SIZE_MAX {
        return Err(ValidationError::new("SELinux context too long"));
    }

    context
        .as_ref()
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '_')
        .then_some(())
        .ok_or_else(|| {
            ValidationError::new(
                "SELinux context must consist of alphanumeric ASCII characters, ':' or '_'",
            )
        })
}

#[test]
fn validate_valid_context() {
    assert!(validate_context("system_u:object_r:container_file_t:s0").is_ok());
}

#[test]
fn validate_context_with_invalid_char() {
    assert!(validate_context("system_u:object_r:container_file_t@s0").is_err());
}

#[test]
fn validate_context_with_space() {
    assert!(validate_context("system_u:object_r: container_file_ts0").is_err());
}

#[test]
fn validate_invalid_empty_context() {
    assert!(validate_context("").is_err());
}

#[test]
fn deserialize_unknown_field() {
    serde_json::from_str::<Selinux>(
        "{
        \"mount_context\": \"system_u:object_r:container_file_t:s0\",
        \"exec\": \"system_u:object_r:container_file_t:s0\",
        \"unknown\": \"system_u:object_r:container_file_t:s0\"
    }",
    )
    .expect_err("unknown field should not be deserialized");
}
