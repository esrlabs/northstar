use nix::{
    libc::EXIT_SUCCESS,
    sys::{self, signal::Signal},
};
use serde::{Deserialize, Serialize};

pub type ExitCode = i32;

/// Container exit status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitStatus {
    /// Process exited with exit code
    Exit(ExitCode),
    /// Process was terminated by a signal
    Signalled(u8),
}

impl From<Signal> for ExitStatus {
    fn from(signal: Signal) -> Self {
        ExitStatus::Signalled(signal as u8)
    }
}

impl From<ExitCode> for ExitStatus {
    fn from(code: ExitCode) -> Self {
        ExitStatus::Exit(code)
    }
}

impl ExitStatus {
    /// Exit success
    pub const SUCCESS: ExitCode = EXIT_SUCCESS;

    /// Was termination successful? Signal termination is not considered a success,
    /// and success is defined as a zero exit status.
    pub fn success(&self) -> bool {
        matches!(self, ExitStatus::Exit(code) if *code == Self::SUCCESS)
    }

    /// Returns the exit code of the process, if any.
    pub fn code(&self) -> Option<ExitCode> {
        match self {
            ExitStatus::Exit(code) => Some(*code),
            ExitStatus::Signalled(_) => None,
        }
    }
}

impl std::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitStatus::Exit(code) => write!(f, "Exit({code})"),
            ExitStatus::Signalled(signal) => match sys::signal::Signal::try_from(*signal as i32) {
                Ok(signal) => write!(f, "Signalled({signal})"),
                Err(_) => write!(f, "Signalled({signal})"),
            },
        }
    }
}
