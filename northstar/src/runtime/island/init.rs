// Copyright (c) 2021 ESRLabs
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

use super::{
    clone::clone, fs::Mount, io::Fd, seccomp::AllowList, Checkpoint, Container, PipeRead, Start,
    SIGNAL_OFFSET,
};
use nix::{
    errno::Errno,
    libc::{self, c_int, c_ulong},
    sched,
    sys::{
        self,
        signal::{signal, sigprocmask, SigHandler, SigSet, SigmaskHow, Signal, SIGCHLD, SIGKILL},
    },
    unistd::{self, Uid},
};
use sched::CloneFlags;
use std::{
    collections::HashSet, env, ffi::CString, io::Read, os::unix::prelude::RawFd, process::exit,
};
use sys::wait::{waitpid, WaitStatus};

// Init function. Pid 1.
#[allow(clippy::too_many_arguments)]
pub(super) fn init(
    container: &Container,
    init: &CString,
    argv: &[CString],
    env: &[CString],
    mounts: &[Mount],
    fds: &[(RawFd, Fd)],
    groups: &[u32],
    seccomp: Option<AllowList>,
    mut checkpoint: Checkpoint,
    tripwire: PipeRead,
) -> ! {
    // Install a "default signal handler" that exits on any signal. This process is the "init"
    // process of this pid ns and therefore doesn't have any own signal handlers. This handler that just exits
    // is needed in case the container is signaled *before* the child is spawned that would otherwise receive the signal.
    // If the child is spawn when the signal is sent to this group it shall exit and the init returns from waitpid.
    set_init_signal_handlers();

    // Become a session group leader
    setsid();

    // Sync with parent
    checkpoint.wait(Start::Start);
    checkpoint.send(Start::Started);
    drop(checkpoint);

    pr_set_name_init();

    // Become a subreaper for orphans in this namespace
    set_child_subreaper(true);

    let manifest = &container.manifest;
    let root = container
        .root
        .canonicalize()
        .expect("Failed to canonicalize root");

    // Mount
    mount(&mounts).expect("Failed to mount");

    // Chroot
    unistd::chroot(&root).expect("Failed to chroot");

    // Pwd
    env::set_current_dir("/").expect("Failed to set cwd to /");

    // UID / GID
    setid(manifest.uid, manifest.gid);

    // Supplementary groups
    setgroups(groups);

    // No new privileges
    set_no_new_privs(true);

    // Capabilities
    drop_capabilities(manifest.capabilities.as_ref());

    // Close and dup fds
    file_descriptors(fds);

    // Clone
    match clone(CloneFlags::empty(), Some(SIGCHLD as i32)) {
        Ok(result) => match result {
            unistd::ForkResult::Parent { child } => {
                wait_for_parent_death(tripwire);

                reset_signal_handlers();

                // Wait for the child to exit
                loop {
                    match waitpid(Some(child), None) {
                        Ok(WaitStatus::Exited(_pid, status)) => exit(status),
                        Ok(WaitStatus::Signaled(_pid, status, _)) => {
                            // Encode the signal number in the process exit status. It's not possible to raise a
                            // a signal in this "init" process that is received by our parent
                            let code = SIGNAL_OFFSET + status as i32;
                            //debug!("Exiting with {} (signaled {})", code, status);
                            exit(code);
                        }
                        Err(e) if e == nix::Error::Sys(Errno::EINTR) => continue,
                        e => panic!("Failed to waitpid on {}: {:?}", child, e),
                    }
                }
            }
            unistd::ForkResult::Child => {
                drop(tripwire);
                set_parent_death_signal(SIGKILL);

                // TODO: Post Linux 5.5 there's a nice clone flag that allows to reset the signal handler during the clone.
                reset_signal_handlers();
                reset_signal_mask();

                // Set seccomp filter
                if let Some(mut filter) = seccomp {
                    filter.apply().expect("Failed to apply seccomp filter.");
                }

                panic!(
                    "Execve: {:?} {:?}: {:?}",
                    &init,
                    &argv,
                    unistd::execve(&init, &argv, &env)
                )
            }
        },
        Err(e) => panic!("Clone error: {}", e),
    }
}

/// Execute list of mount calls
fn mount(mounts: &[Mount]) -> Result<(), ()> {
    for mount in mounts {
        mount.mount()?;
    }
    Ok(())
}

/// Apply file descriptor configuration
fn file_descriptors(map: &[(RawFd, Fd)]) {
    for (fd, value) in map {
        match value {
            Fd::Close => {
                unistd::close(*fd).ok();
            } // Ignore close errors because the fd list contains the ReadDir fd and fds from other tasks.
            Fd::Dup(n) => {
                unistd::dup2(*n, *fd).expect("Failed to dup2");
                unistd::close(*n).expect("Failed to close");
            }
        }
    }
}

fn set_child_subreaper(value: bool) {
    #[cfg(target_os = "android")]
    const PR_SET_CHILD_SUBREAPER: c_int = 36;
    #[cfg(not(target_os = "android"))]
    use libc::PR_SET_CHILD_SUBREAPER;

    let value = if value { 1u64 } else { 0u64 };
    let result = unsafe { nix::libc::prctl(PR_SET_CHILD_SUBREAPER, value, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .expect("Failed to set PR_SET_CHILD_SUBREAPER");
}

fn set_parent_death_signal(signal: Signal) {
    #[cfg(target_os = "android")]
    const PR_SET_PDEATHSIG: c_int = 1;
    #[cfg(not(target_os = "android"))]
    use libc::PR_SET_PDEATHSIG;

    let result = unsafe { nix::libc::prctl(PR_SET_PDEATHSIG, signal, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .expect("Failed to set PR_SET_PDEATHSIG");
}

/// Wait in a separate thread for the parent (runtime) process to terminate. This should normally
/// not happen. If it does, we (init) need to terminate ourselves or we will be adopted by system
/// init. Setting PR_SET_PDEATHSIG is not an option here as we were spawned from a short lived tokio
/// thread (not process) that would trigger the signal once the thread terminates.
/// Performing this step before calling setgroups results in a SIGABRT.
fn wait_for_parent_death(mut tripwire: PipeRead) {
    std::thread::spawn(move || {
        tripwire.read_exact(&mut [0u8, 1]).ok();
        panic!("Runtime died");
    });
}

fn set_no_new_privs(value: bool) {
    #[cfg(target_os = "android")]
    pub const PR_SET_NO_NEW_PRIVS: c_int = 38;
    #[cfg(not(target_os = "android"))]
    use libc::PR_SET_NO_NEW_PRIVS;

    let result = unsafe { nix::libc::prctl(PR_SET_NO_NEW_PRIVS, value as c_ulong, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .expect("Failed to set PR_SET_NO_NEW_PRIVS")
}

#[cfg(target_os = "android")]
pub const PR_SET_NAME: c_int = 15;
#[cfg(not(target_os = "android"))]
use libc::PR_SET_NAME;

/// Set the name of the current process to "init"
fn pr_set_name_init() {
    let cname = "init\0";
    let result = unsafe { libc::prctl(PR_SET_NAME, cname.as_ptr() as c_ulong, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .expect("Failed to set PR_SET_NAME");
}

/// Install default signal handler
fn reset_signal_handlers() {
    Signal::iterator()
        .filter(|s| *s != Signal::SIGCHLD)
        .filter(|s| *s != Signal::SIGKILL)
        .filter(|s| *s != Signal::SIGSTOP)
        .try_for_each(|s| unsafe { signal(s, SigHandler::SigDfl) }.map(drop))
        .expect("failed to signal");
}

fn reset_signal_mask() {
    sigprocmask(SigmaskHow::SIG_UNBLOCK, Some(&SigSet::all()), None)
        .expect("Failed to reset signal maks")
}

/// Install a signal handler that terminates the init process if the signal
/// is received before the clone of the child. If this handler would not be
/// installed the signal would be ignored (and not sent to the group) because
/// the init processes in PID namespace do not have default signal handlers.
fn set_init_signal_handlers() {
    extern "C" fn init_signal_handler(signal: c_int) {
        exit(SIGNAL_OFFSET + signal);
    }

    Signal::iterator()
        .filter(|s| *s != Signal::SIGCHLD)
        .filter(|s| *s != Signal::SIGKILL)
        .filter(|s| *s != Signal::SIGSTOP)
        .try_for_each(|s| unsafe { signal(s, SigHandler::Handler(init_signal_handler)) }.map(drop))
        .expect("Failed to set signal handler");
}

// Reset effective caps to the most possible set
fn reset_effective_caps() {
    caps::set(None, caps::CapSet::Effective, &caps::all()).expect("Failed to reset effective caps");
}

/// Set uid/gid
fn setid(uid: u32, gid: u32) {
    let rt_priveleged = unistd::geteuid() == Uid::from_raw(0);

    // If running as uid 0 save our caps across the uid/gid drop
    if rt_priveleged {
        caps::securebits::set_keepcaps(true).expect("Failed to set keep caps");
    }

    let gid = unistd::Gid::from_raw(gid);
    unistd::setresgid(gid, gid, gid).expect("Failed to set resgid");

    let uid = unistd::Uid::from_raw(uid);
    unistd::setresuid(uid, uid, uid).expect("Failed to set resuid");

    if rt_priveleged {
        reset_effective_caps();
        caps::securebits::set_keepcaps(false).expect("Failed to set keep caps");
    }
}

/// Become a session group leader
fn setsid() {
    unistd::setsid().expect("Failed to call setsid");
}

fn setgroups(groups: &[u32]) {
    let result = unsafe { nix::libc::setgroups(groups.len(), groups.as_ptr()) };

    Errno::result(result)
        .map(drop)
        .expect("Failed to set supplementary groups");
}

/// Drop capabilities
fn drop_capabilities(cs: Option<&HashSet<caps::Capability>>) {
    let mut bounded =
        caps::read(None, caps::CapSet::Bounding).expect("Failed to read bounding caps");
    if let Some(caps) = cs {
        bounded.retain(|c| !caps.contains(c));
    }

    for cap in bounded {
        // caps::set cannot be called for bounded
        caps::drop(None, caps::CapSet::Bounding, cap).expect("Failed to drop bounding cap");
    }

    if let Some(caps) = cs {
        caps::set(None, caps::CapSet::Effective, caps).expect("Failed to set effective caps");
        caps::set(None, caps::CapSet::Permitted, caps).expect("Failed to set permitted caps");
        caps::set(None, caps::CapSet::Inheritable, caps).expect("Failed to set inheritable caps");
        caps::set(None, caps::CapSet::Ambient, caps).expect("Failed to set ambient caps");
    }
}
