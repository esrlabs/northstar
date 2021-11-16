use crate::{
    debug, error,
    runtime::{error::Error, Pid},
};
use nix::{
    errno::Errno,
    libc::{self, c_ulong},
    sys::signal::Signal,
    unistd::{self},
};
use std::process::exit;

/// Set the parent death signal of the calling process
pub fn set_parent_death_signal(signal: Signal) {
    #[cfg(target_os = "android")]
    const PR_SET_PDEATHSIG: libc::c_int = 1;
    #[cfg(not(target_os = "android"))]
    use libc::PR_SET_PDEATHSIG;

    debug!("Setting parent death signal to {}", signal);

    let result = unsafe { nix::libc::prctl(PR_SET_PDEATHSIG, signal, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .expect("Failed to set PR_SET_PDEATHSIG");
}

/// Set the name of the current process
pub fn set_process_name(name: &str) {
    #[cfg(target_os = "android")]
    const PR_SET_NAME: libc::c_int = 15;
    #[cfg(not(target_os = "android"))]
    use libc::PR_SET_NAME;

    debug!("Setting process name to {}", name);

    // PR_SET_NAME (since Linux 2.6.9)
    // Set the name of the calling thread, using the value in the
    // location pointed to by (char *) arg2.  The name can be up
    // to 16 bytes long, including the terminating null byte.
    // (If the length of the string, including the terminating
    // null byte, exceeds 16 bytes, the string is silently
    // truncated.)  This is the same attribute that can be set
    // via pthread_setname_np(3) and retrieved using
    // pthread_getname_np(3).  The attribute is likewise
    // accessible via /proc/self/task/[tid]/comm (see proc(5)),
    // where [tid] is the thread ID of the calling thread, as
    // returned by gettid(2).
    let mut name = name.as_bytes().to_vec();
    name.truncate(15);
    name.push(b'\0');

    let result = unsafe { libc::prctl(PR_SET_NAME, name.as_ptr() as c_ulong, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .expect("Failed to set PR_SET_NAME");
}

// Set the child subreaper flag of the calling thread
pub fn set_child_subreaper(value: bool) {
    #[cfg(target_os = "android")]
    const PR_SET_CHILD_SUBREAPER: nix::libc::c_int = 36;
    #[cfg(not(target_os = "android"))]
    use nix::libc::PR_SET_CHILD_SUBREAPER;

    debug!("Setting child subreaper flag to {}", value);

    let value = if value { 1u64 } else { 0u64 };
    let result = unsafe { nix::libc::prctl(PR_SET_CHILD_SUBREAPER, value, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .expect("Failed to set child subreaper flag")
}

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
        unistd::ForkResult::Parent { child } => Ok(child.as_raw() as Pid),
        unistd::ForkResult::Child => match f() {
            Ok(_) => exit(0),
            Err(e) => {
                error!("Failed after fork: {:?}", e);
                exit(-1);
            }
        },
    }
}

pub(crate) static mut LOG_TARGET: String = String::new();

pub(crate) fn set_log_target(tag: String) {
    unsafe {
        LOG_TARGET = tag;
    }
}

/// Log to debug
#[allow(unused)]
#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => (
        assert!(unsafe { !crate::runtime::fork::util::LOG_TARGET.is_empty() });
        log::debug!(target: unsafe { crate::runtime::fork::util::LOG_TARGET.as_str() }, $($arg)+)
    )
}

/// Log to info
#[allow(unused)]
#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => (
        assert!(unsafe { !crate::runtime::fork::util::LOG_TARGET.is_empty() });
        log::info!(target: unsafe { crate::runtime::fork::util::LOG_TARGET.as_str() }, $($arg)+)
    )
}

/// Log to warn
#[allow(unused)]
#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => (
        assert!(unsafe { !crate::runtime::fork::util::LOG_TARGET.is_empty() });
        log::warn!(target: unsafe { crate::runtime::fork::util::LOG_TARGET.as_str() }, $($arg)+)
    )
}

/// Log to error
#[allow(unused)]
#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => (
        assert!(unsafe { !crate::runtime::fork::util::LOG_TARGET.is_empty() });
        log::error!(target: unsafe { crate::runtime::fork::util::LOG_TARGET.as_str() }, $($arg)+)
    )
}
