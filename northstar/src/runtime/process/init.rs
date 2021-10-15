use super::{fs::Mount, io::Fd, Capabilities, RLimits};
use crate::{
    runtime::{
        pipe::{Channel, ConditionNotify},
        ExitStatus,
    },
    seccomp::AllowList,
};
use nix::{
    errno::Errno,
    libc::{self, c_ulong},
    sched::unshare,
    sys::wait::{waitpid, WaitStatus},
    unistd::{self, Uid},
};
use std::{env, ffi::CString, os::unix::prelude::RawFd, path::PathBuf, process::exit};

pub(super) struct Init {
    pub root: PathBuf,
    pub init: CString,
    pub argv: Vec<CString>,
    pub env: Vec<CString>,
    pub uid: u16,
    pub gid: u16,
    pub mounts: Vec<Mount>,
    pub fds: Vec<(RawFd, Fd)>,
    pub groups: Vec<u32>,
    pub capabilities: Capabilities,
    pub rlimits: RLimits,
    pub seccomp: Option<AllowList>,
}

impl Init {
    pub(super) fn run(
        self,
        condition_notify: ConditionNotify,
        mut exit_status_channel: Channel,
    ) -> ! {
        // Set the process name to init. This process inherited the process name
        // from the runtime
        set_process_name();

        // Become a session group leader
        unistd::setsid().expect("Failed to call setsid");

        // Enter mount namespace
        unshare(nix::sched::CloneFlags::CLONE_NEWNS).expect("Failed to unshare NEWNS");

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

        // Apply resource limits
        self.set_rlimits();

        // No new privileges
        set_no_new_privs(true);

        // Capabilities
        self.drop_privileges();

        // Close and dup fds
        self.file_descriptors();

        // Clone
        match unsafe { unistd::fork() } {
            Ok(result) => match result {
                unistd::ForkResult::Parent { child } => {
                    // Drop checkpoint. The fds are cloned into the child and are closed upon execve.
                    drop(condition_notify);

                    // Wait for the child to exit
                    loop {
                        match waitpid(Some(child), None) {
                            Ok(WaitStatus::Exited(_pid, status)) => {
                                let exit_status = ExitStatus::Exit(status);
                                exit_status_channel
                                    .send(&exit_status)
                                    .expect("Failed to send exit status");
                                exit(0);
                            }
                            Ok(WaitStatus::Signaled(_pid, status, _)) => {
                                let exit_status = ExitStatus::Signalled(status as u8);
                                exit_status_channel
                                    .send(&exit_status)
                                    .expect("Failed to send exit status");
                                exit(0);
                            }
                            Ok(WaitStatus::Continued(_)) | Ok(WaitStatus::Stopped(_, _)) => {
                                continue
                            }
                            Err(nix::Error::EINTR) => continue,
                            e => panic!("Failed to waitpid on {}: {:?}", child, e),
                        }
                    }
                }
                unistd::ForkResult::Child => {
                    drop(exit_status_channel);

                    // Set seccomp filter
                    if let Some(ref filter) = self.seccomp {
                        filter.apply().expect("Failed to apply seccomp filter.");
                    }

                    // Checkpoint fds are FD_CLOEXEC and act as a signal for the launcher that this child is started.
                    // Therefore no explicit drop (close) of _checkpoint_notify is needed here.
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
        let uid = self.uid;
        let gid = self.gid;

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

    fn set_rlimits(&self) {
        for (r, l) in &self.rlimits {
            r.set(
                l.soft.unwrap_or(rlimit::INFINITY),
                l.hard.unwrap_or(rlimit::INFINITY),
            )
            .expect("Failed to set rlimit");
        }
    }

    /// Drop capabilities
    fn drop_privileges(&self) {
        for cap in &self.capabilities.bounded {
            // caps::set cannot be called for bounded
            caps::drop(None, caps::CapSet::Bounding, *cap).expect("Failed to drop bounding cap");
        }
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
