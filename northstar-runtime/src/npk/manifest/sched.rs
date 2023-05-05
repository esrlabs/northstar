use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

/// Policy.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    /// The standard round-robin time-sharing policy.
    Other,
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
    Batch,
    /// Running very low priority background jobs.
    Idle,
    /// Deadline policy.
    Deadline,
}

/// Scheduling policy.
#[derive(Clone, Default, Eq, PartialEq, Debug, Serialize, Validate, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Sched {
    /// Scheduling policy.
    #[validate(custom = "validate_policy")]
    pub policy: Option<Policy>,
    /// Nice level. +19 (low priority) to -20 (high
    #[validate(range(min = -20, max = 19, message = "nice value must be between -20 and 19"))]
    pub nice: Option<i8>,
}

fn validate_policy(policy: &Policy) -> Result<(), ValidationError> {
    match policy {
        Policy::Fifo { priority } if !(1u32..=99).contains(priority) => {
            let mut error = ValidationError::new("fifo priority must be between 1 and 99");
            error.add_param("priority".into(), priority);
            Err(error)
        }
        Policy::RoundRobin { priority } => {
            let mut error = ValidationError::new("round robing priority must be between 1 and 99");
            error.add_param("priority".into(), priority);
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
            serde_yaml::from_str::<Sched>("policy: other")?,
            Sched {
                policy: Some(Policy::Other),
                nice: None
            }
        );
        Ok(())
    }

    #[test]
    fn parse_other_with_nice_value() -> Result<()> {
        assert_eq!(
            serde_yaml::from_str::<Sched>("policy: other\nnice: 10")?,
            Sched {
                policy: Some(Policy::Other),
                nice: Some(10)
            }
        );
        Ok(())
    }

    #[test]
    fn parse_other_with_too_big_nice_value() -> Result<()> {
        let policy = serde_yaml::from_str::<Sched>("policy: other\nnice: 55")?;
        assert!(policy.validate().is_err());
        Ok(())
    }

    #[test]
    fn parse_other_with_too_small_nice_value() -> Result<()> {
        let policy = serde_yaml::from_str::<Sched>("policy: other\nnice: -40")?;
        assert!(policy.validate().is_err());
        Ok(())
    }

    #[test]
    fn parse_fifo() -> Result<()> {
        assert_eq!(
            serde_yaml::from_str::<Sched>("policy:\n  !fifo\n    priority: 10")?,
            Sched {
                policy: Some(Policy::Fifo { priority: 10 }),
                nice: None
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
