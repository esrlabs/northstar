use validator::ValidationError;

pub use crate::seccomp::{Seccomp, SyscallRule};

/// Validate seccomp rules
pub(crate) fn validate(seccomp: &Seccomp) -> Result<(), ValidationError> {
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
