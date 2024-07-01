use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

/// Policy.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    /// The standard round-robin time-sharing policy.
    Other {
        /// Nice level. +19 (low priority) to -20 (high
        nice: i8,
    },
    /// First-in, first-out policy.
    Fifo {
        /// Priority of the process.
        priority: u32,
    },
    /// Round-robin policy.
    RoundRobin {
        /// Priority of the process.
        priority: u32,
    },
    /// Batch style execution of processes.
    Batch {
        /// Nice level. +19 (low priority) to -20 (high
        nice: i8,
    },
    /// Running very low priority background jobs.
    Idle,
    /// Deadline policy.
    Deadline,
}

/// Scheduling policy.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Validate, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Sched {
    /// Scheduling policy.
    #[validate(custom(function = "validate_policy"))]
    pub policy: Policy,
}

fn validate_policy(policy: &Policy) -> Result<(), ValidationError> {
    match policy {
        Policy::Other { nice } if !(-20..=19).contains(nice) => {
            let mut error = ValidationError::new("nice must be between -20 and 19");
            error.add_param("nice".into(), nice);
            Err(error)
        }
        Policy::Fifo { priority } if !(1..=99).contains(priority) => {
            let mut error = ValidationError::new("fifo priority must be between 1 and 99");
            error.add_param("priority".into(), priority);
            Err(error)
        }
        Policy::RoundRobin { priority } => {
            let mut error = ValidationError::new("round robing priority must be between 1 and 99");
            error.add_param("priority".into(), priority);
            Err(error)
        }
        Policy::Batch { nice } if !(-20..=19).contains(nice) => {
            let mut error = ValidationError::new("nice must be between -20 and 19");
            error.add_param("nice".into(), nice);
            Err(error)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod test {
    use super::{Policy, Sched};
    use anyhow::Result;
    use validator::Validate;

    #[test]
    fn parse_other() -> Result<()> {
        assert_eq!(
            serde_yaml::from_str::<Sched>("policy:\n  !other\n    nice: 0")?,
            Sched {
                policy: Policy::Other { nice: 0 },
            }
        );
        Ok(())
    }

    #[test]
    fn parse_other_with_nice_value() -> Result<()> {
        assert_eq!(
            serde_yaml::from_str::<Sched>("policy:\n  !other\n    nice: 10")?,
            Sched {
                policy: Policy::Other { nice: 10 },
            }
        );
        Ok(())
    }

    #[test]
    fn parse_other_with_too_big_nice_value() -> Result<()> {
        let policy = serde_yaml::from_str::<Sched>("policy:\n  !other\n    nice: 55")?;
        assert!(policy.validate().is_err());
        Ok(())
    }

    #[test]
    fn parse_other_with_too_small_nice_value() -> Result<()> {
        let policy = serde_yaml::from_str::<Sched>("policy:\n  !other\n    nice: -40")?;
        assert!(policy.validate().is_err());
        Ok(())
    }

    #[test]
    fn parse_fifo() -> Result<()> {
        assert_eq!(
            serde_yaml::from_str::<Sched>("policy:\n  !fifo\n    priority: 10")?,
            Sched {
                policy: Policy::Fifo { priority: 10 },
            }
        );
        Ok(())
    }

    #[test]
    fn parse_fifo_with_zero_priority() -> Result<()> {
        assert!(
            serde_yaml::from_str::<Sched>("policy:\n  !fifo\n    priority: 0")?
                .validate()
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn parse_fifo_with_too_high_priority() -> Result<()> {
        assert!(
            serde_yaml::from_str::<Sched>("policy:\n  !fifo\n    priority: 200")?
                .validate()
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn parse_round_robing_with_too_zero_priority() -> Result<()> {
        assert!(
            serde_yaml::from_str::<Sched>("policy:\n  !round_robin\n    priority: 0")?
                .validate()
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn parse_round_robing_with_too_high_priority() -> Result<()> {
        assert!(
            serde_yaml::from_str::<Sched>("policy:\n  !round_robin\n    priority: 200")?
                .validate()
                .is_err()
        );
        Ok(())
    }
}
