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
    clone::clone, fs::Mount, io::Fd, seccomp::AllowList, Capabilities, Checkpoint, SIGNAL_OFFSET,
};
use crate::npk::manifest::Manifest;
use nix::{
    errno::Errno,
    libc::{self, c_ulong},
    sched,
    sys::{
        self,
        signal::{Signal, SIGCHLD, SIGKILL},
        wait::WaitPidFlag,
    },
    unistd::{self, Uid},
};
use sched::CloneFlags;
use std::{env, ffi::CString, os::unix::prelude::RawFd, path::PathBuf, process::exit};
use sys::wait::{waitpid, WaitStatus};

pub(super) struct Init {
    pub manifest: Manifest,
    pub root: PathBuf,
    pub init: CString,
    pub argv: Vec<CString>,
    pub env: Vec<CString>,
    pub mounts: Vec<Mount>,
    pub fds: Vec<(RawFd, Fd)>,
    pub groups: Vec<u32>,
    pub capabilities: Capabilities,
    pub seccomp: Option<AllowList>,
    pub checkpoint: Checkpoint,
}

impl Init {
    pub(super) fn run(self) -> ! {
        // Set the process name to init. This process inherited the process name
        // from the runtime
        set_process_name();

        // If the runtime dies we want to die as well
        set_parent_death_signal(SIGKILL);

        // Become a session group leader
        unistd::setsid().expect("Failed to call setsid");

        // Become a subreaper for orphans in this namespace
        set_child_subreaper(true);

        // Perform all mounts passed in mounts
        mount(&self.mounts);

        // Set the chroot to the containers root mount point
        unistd::chroot(&self.root).expect("Failed to chroot");

        // Set current working directory to root
        env::set_current_dir("/").expect("Failed to set cwd to /");

        // UID / GID
        self.set_ids();

        // Supplementary groups
        self.set_groups();

        // No new privileges
        set_no_new_privs(true);

        // Capabilities
        self.drop_privileges();

        // Close and dup fds
        self.file_descriptors();

        // Clone
        match clone(CloneFlags::empty(), Some(SIGCHLD as i32)) {
            Ok(result) => match result {
                unistd::ForkResult::Parent { child } => {
                    // Drop checkpoint. The fds are cloned into the child and are closed upon execve.
                    drop(self.checkpoint);

                    // Wait for the child to exit
                    loop {
                        match waitpid(Some(child), Some(WaitPidFlag::__WALL)) {
                            Ok(WaitStatus::Exited(_pid, status)) => exit(status),
                            Ok(WaitStatus::Signaled(_pid, status, _)) => {
                                // Encode the signal number in the process exit status. It's not possible to raise a
                                // a signal in this "init" process that is received by our parent
                                let code = SIGNAL_OFFSET + status as i32;
                                //debug!("Exiting with {} (signaled {})", code, status);
                                exit(code);
                            }
                            Ok(WaitStatus::Continued(_)) | Ok(WaitStatus::Stopped(_, _)) => {
                                continue
                            }
                            Err(e) if e == nix::Error::Sys(Errno::EINTR) => continue,
                            e => panic!("Failed to waitpid on {}: {:?}", child, e),
                        }
                    }
                }
                unistd::ForkResult::Child => {
                    // If init dies, we want to die as well. This should normally never happen and is a error condition.
                    set_parent_death_signal(SIGKILL);

                    // Unblock signals. The signal mask has been set in the runtime prior to the clone call. This
                    // avoids that init receives signals which are unhandled. Reminder: init doesn't have any
                    // signals handlers because it's init of a PID ns.
                    super::signals_unblock();

                    // Set seccomp filter
                    if let Some(ref filter) = self.seccomp {
                        filter.apply().expect("Failed to apply seccomp filter.");
                    }

                    // Wait for the runtime to signal that the child shall start
                    // checkoint fds are cloexec and this signals the launcher that this child is started
                    // Therefore no explicity drop (close) of _checkpoint_notify here.
                    let _checkpoint_notify = self.checkpoint.wait();

                    panic!(
                        "Execve: {:?} {:?}: {:?}",
                        &self.init,
                        &self.argv,
                        unistd::execve(&self.init, &self.argv, &self.env)
                    )
                }
            },
            Err(e) => panic!("Clone error: {}", e),
        }
    }

    /// Set uid/gid
    fn set_ids(&self) {
        let uid = self.manifest.uid;
        let gid = self.manifest.gid;

        let rt_privileged = unistd::geteuid() == Uid::from_raw(0);

        // If running as uid 0 save our caps across the uid/gid drop
        if rt_privileged {
            caps::securebits::set_keepcaps(true).expect("Failed to set keep caps");
        }

        let gid = unistd::Gid::from_raw(gid.into());
        unistd::setresgid(gid, gid, gid).expect("Failed to set resgid");

        let uid = unistd::Uid::from_raw(uid.into());
        unistd::setresuid(uid, uid, uid).expect("Failed to set resuid");

        if rt_privileged {
            self.reset_effective_caps();
            caps::securebits::set_keepcaps(false).expect("Failed to set keep caps");
        }
    }

    fn set_groups(&self) {
        let result = unsafe { nix::libc::setgroups(self.groups.len(), self.groups.as_ptr()) };

        Errno::result(result)
            .map(drop)
            .expect("Failed to set supplementary groups");
    }

    /// Drop capabilities
    fn drop_privileges(&self) {
        for cap in &self.capabilities.bounded {
            // caps::set cannot be called for bounded
            caps::drop(None, caps::CapSet::Bounding, *cap).expect("Failed to drop bounding cap");
        }
        // caps::set(None, caps::CapSet::Bounding, &self.capabilities.bounded)
        //     .expect("Failed to set effective caps");
        caps::set(None, caps::CapSet::Effective, &self.capabilities.set)
            .expect("Failed to set effective caps");
        caps::set(None, caps::CapSet::Permitted, &self.capabilities.set)
            .expect("Failed to set permitted caps");
        caps::set(None, caps::CapSet::Inheritable, &self.capabilities.set)
            .expect("Failed to set inheritable caps");
        caps::set(None, caps::CapSet::Ambient, &self.capabilities.set)
            .expect("Failed to set ambient caps");
    }

    // Reset effective caps to the most possible set
    fn reset_effective_caps(&self) {
        caps::set(None, caps::CapSet::Effective, &self.capabilities.all)
            .expect("Failed to reset effective caps");
    }

    /// Apply file descriptor configuration
    fn file_descriptors(&self) {
        for (fd, value) in &self.fds {
            match value {
                Fd::Close => {
                    // Ignore close errors because the fd list contains the ReadDir fd and fds from other tasks.
                    unistd::close(*fd).ok();
                }
                Fd::Dup(n) => {
                    unistd::dup2(*n, *fd).expect("Failed to dup2");
                    unistd::close(*n).expect("Failed to close");
                }
            }
        }
    }
}

/// Execute list of mount calls
fn mount(mounts: &[Mount]) {
    for mount in mounts {
        mount.mount();
    }
}

fn set_child_subreaper(value: bool) {
    #[cfg(target_os = "android")]
    const PR_SET_CHILD_SUBREAPER: libc::c_int = 36;
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
    const PR_SET_PDEATHSIG: libc::c_int = 1;
    #[cfg(not(target_os = "android"))]
    use libc::PR_SET_PDEATHSIG;

    let result = unsafe { nix::libc::prctl(PR_SET_PDEATHSIG, signal, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .expect("Failed to set PR_SET_PDEATHSIG");
}

fn set_no_new_privs(value: bool) {
    #[cfg(target_os = "android")]
    pub const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
    #[cfg(not(target_os = "android"))]
    use libc::PR_SET_NO_NEW_PRIVS;

    let result = unsafe { nix::libc::prctl(PR_SET_NO_NEW_PRIVS, value as c_ulong, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .expect("Failed to set PR_SET_NO_NEW_PRIVS")
}

#[cfg(target_os = "android")]
pub const PR_SET_NAME: libc::c_int = 15;
#[cfg(not(target_os = "android"))]
use libc::PR_SET_NAME;

/// Set the name of the current process to "init"
fn set_process_name() {
    let cname = "init\0";
    let result = unsafe { libc::prctl(PR_SET_NAME, cname.as_ptr() as c_ulong, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .expect("Failed to set PR_SET_NAME");
}
