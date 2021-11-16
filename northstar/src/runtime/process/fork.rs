use nix::unistd::{self, Pid};

use crate::runtime::error::Error;

/// Fork a new process.
///
/// # Arguments:
///
/// * `f` - The closure to run in the child process.
///
pub fn fork<F>(f: F) -> nix::Result<Pid>
where
    F: FnOnce() -> Result<(), Error>,
{
    match unsafe { unistd::fork()? } {
        unistd::ForkResult::Parent { child } => Ok(child),
        unistd::ForkResult::Child => {
            if let Err(e) = f() {
                log::error!("Failed after fork: {:?}", e);
                std::process::exit(-1);
            }
            std::process::exit(0);
        }
    }
}
