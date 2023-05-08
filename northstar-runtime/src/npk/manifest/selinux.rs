use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

use crate::common::non_nul_string::NonNulString;

/// SELinux configuration
#[derive(Clone, Eq, PartialEq, Debug, Validate, Serialize, Deserialize)]
pub struct Selinux {
    /// Explicit list of allowed syscalls
    #[validate(custom = "validate_context")]
    pub context: NonNulString,
}

/// Validate selinux settings
pub fn validate_context(context: &NonNulString) -> Result<(), ValidationError> {
    // Maximum length since at least Linux v3.7
    // (https://elixir.bootlin.com/linux/v3.7/source/include/uapi/linux/limits.h)
    const XATTR_SIZE_MAX: usize = 65536;

    if context.len() >= XATTR_SIZE_MAX {
        return Err(ValidationError::new("Selinux context too long"));
    }

    if !context
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '_')
    {
        return Err(ValidationError::new(
            "Selinux context must consist of alphanumeric ASCII characters, '?' or '_'",
        ));
    }

    Ok(())
}
