use super::{fs::Mount, io::Fd};
use crate::{
    npk::manifest::{Capability, RLimitResource, RLimitValue},
    runtime::{ipc::channel, process::fork::fork, ExitStatus},
    seccomp::AllowList,
};

use nix::{
    errno::Errno,
    libc::{self, c_ulong},
    sched::unshare,
    sys::wait::{waitpid, WaitStatus},
    unistd::{self, Uid},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    env,
    ffi::CString,
    os::unix::prelude::{AsRawFd, RawFd},
    path::PathBuf,
    process::exit,
    sync::mpsc,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Init {
    pub root: PathBuf,
    pub uid: u16,
    pub gid: u16,
    pub mounts: Vec<Mount>,
    pub fds: Vec<(RawFd, Fd)>,
    pub groups: Vec<u32>,
    pub capabilities: Option<HashSet<Capability>>,
    pub rlimits: Option<HashMap<RLimitResource, RLimitValue>>,
    pub seccomp: Option<AllowList>,
}

/// This is the type used to communicate with the init process from the runtime.
#[derive(Debug, Serialize, Deserialize)]
pub enum InitMessage {
    Forked { pid: i32 },
    Exit { pid: i32, exit_status: ExitStatus },
}

/// Command execution request
#[derive(Debug, Serialize, Deserialize)]
pub struct Exec {
    pub path: CString,
    pub args: Vec<CString>,
    pub env: Vec<CString>,
}

/// Init process main function
fn init_main(
    mut rt_tx: channel::Sender<InitMessage>,
    mut rt_rx: channel::Receiver<Exec>,
    seccomp: Option<AllowList>,
) -> ! {
    enum Event {
        Exit { pid: i32, exit_status: ExitStatus },
        Command(Exec),
    }
    let (tx, rx) = mpsc::channel();

    // This thread forwards the commands coming from the runtime
    let command_tx = tx.clone();
    std::thread::spawn(move || loop {
        let command = rt_rx
            .recv()
            .expect("Failed to receive init command from runtime");
        command_tx.send(Event::Command(command)).unwrap();
    });

    // This thread sends the exit status of the child processes
    let exit_status_tx = tx;
    let reaper_thread = std::thread::spawn(move || {
        loop {
            match waitpid(None, None) {
                Ok(WaitStatus::Exited(pid, status)) => {
                    exit_status_tx
                        .send(Event::Exit {
                            pid: pid.as_raw(),
                            exit_status: ExitStatus::Exit(status),
                        })
                        .unwrap();
                }
                Ok(WaitStatus::Signaled(pid, status, _)) => {
                    exit_status_tx
                        .send(Event::Exit {
                            pid: pid.as_raw() as i32,
                            exit_status: ExitStatus::Signalled(status as u8),
                        })
                        .unwrap();
                }
                Ok(WaitStatus::Continued(_)) | Ok(WaitStatus::Stopped(_, _)) => continue,
                Err(Errno::ECHILD) => {
                    // wait till a child process is spawned
                    // unparked by the consumer thread after a Exec is received
                    std::thread::park();
                }
                e => panic!("Failed to waitpid: {:?}", e),
            }
        }
    });

    // Consume messages from threads
    loop {
        match rx.recv() {
            Ok(Event::Exit { pid, exit_status }) => {
                rt_tx
                    .send(InitMessage::Exit { pid, exit_status })
                    .expect("Failed to send exit status");

                // Note:
                // Currently the init process exists after the first child
                // process exits.
                exit(0);
            }
            Ok(Event::Command(Exec { path, args, env })) => {
                // Start new process inside the container
                let child_pid = fork(|| {
                    // Set seccomp filter
                    if let Some(ref filter) = seccomp {
                        filter.apply().expect("Failed to apply seccomp filter.");
                    }

                    // Checkpoint fds are FD_CLOEXEC and act as a signal for the launcher that this child
                    // is started. Therefore no explicit drop (close) of _checkpoint_notify is needed here.
                    panic!(
                        "Execve: {:?} {:?}: {:?}",
                        &path,
                        &args,
                        unistd::execve(&path, &args, &env)
                    )
                })
                .expect("Failed to spawn child process");

                rt_tx
                    .send(InitMessage::Forked {
                        pid: child_pid.as_raw(),
                    })
                    .expect("Failed to send exit status");

                // wake up the reaper thread
                reaper_thread.thread().unpark();
            }
            Err(e) => {
                panic!("Failed to receive message: {}", e);
            }
        }
    }
}

impl Init {
    pub(super) fn run(
        self,
        rt_tx: channel::Sender<InitMessage>,
        rt_rx: channel::Receiver<Exec>,
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
        // Avoid clossing accidentally the channel file descriptors
        self.file_descriptors(&[rt_tx.as_raw_fd(), rt_rx.as_raw_fd()]);

        // We need to clone from the reference to be able to "move" the channel into the thread
        init_main(rt_tx, rt_rx, self.seccomp)
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
        if let Some(limits) = self.rlimits.as_ref() {
            for (resource, limit) in limits {
                let resource = match resource {
                    RLimitResource::AS => rlimit::Resource::AS,
                    RLimitResource::CORE => rlimit::Resource::CORE,
                    RLimitResource::CPU => rlimit::Resource::CPU,
                    RLimitResource::DATA => rlimit::Resource::DATA,
                    RLimitResource::FSIZE => rlimit::Resource::FSIZE,
                    RLimitResource::LOCKS => rlimit::Resource::LOCKS,
                    RLimitResource::MEMLOCK => rlimit::Resource::MEMLOCK,
                    RLimitResource::MSGQUEUE => rlimit::Resource::MSGQUEUE,
                    RLimitResource::NICE => rlimit::Resource::NICE,
                    RLimitResource::NOFILE => rlimit::Resource::NOFILE,
                    RLimitResource::NPROC => rlimit::Resource::NPROC,
                    RLimitResource::RSS => rlimit::Resource::RSS,
                    RLimitResource::RTPRIO => rlimit::Resource::RTPRIO,
                    #[cfg(not(target_os = "android"))]
                    RLimitResource::RTTIME => rlimit::Resource::RTTIME,
                    RLimitResource::SIGPENDING => rlimit::Resource::SIGPENDING,
                    RLimitResource::STACK => rlimit::Resource::STACK,
                };
                resource
                    .set(
                        limit.soft.unwrap_or(rlimit::INFINITY),
                        limit.hard.unwrap_or(rlimit::INFINITY),
                    )
                    .expect("Failed to set rlimit");
            }
        }
    }

    /// Drop capabilities
    fn drop_privileges(&self) {
        let mut bounded =
            caps::read(None, caps::CapSet::Bounding).expect("Failed to read bounding caps");
        // Convert the set from the manifest to a set of caps::Capbility
        let set = self
            .capabilities
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(Into::into)
            .collect::<HashSet<caps::Capability>>();
        bounded.retain(|c| !set.contains(c));

        for cap in &bounded {
            // caps::set cannot be called for bounded
            caps::drop(None, caps::CapSet::Bounding, *cap).expect("Failed to drop bounding cap");
        }
        caps::set(None, caps::CapSet::Effective, &set).expect("Failed to set effective caps");
        caps::set(None, caps::CapSet::Permitted, &set).expect("Failed to set permitted caps");
        caps::set(None, caps::CapSet::Inheritable, &set).expect("Failed to set inheritable caps");
        caps::set(None, caps::CapSet::Ambient, &set).expect("Failed to set ambient caps");
    }

    // Reset effective caps to the most possible set
    fn reset_effective_caps(&self) {
        let all = caps::all();
        caps::set(None, caps::CapSet::Effective, &all).expect("Failed to reset effective caps");
    }

    /// Apply file descriptor configuration
    fn file_descriptors(&self, skip: &[RawFd]) {
        let skip: HashSet<&RawFd> = skip.iter().collect();

        for (fd, value) in &self.fds {
            if skip.contains(&fd) {
                continue;
            }

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

impl From<Capability> for caps::Capability {
    fn from(cap: Capability) -> Self {
        match cap {
            Capability::CAP_CHOWN => caps::Capability::CAP_CHOWN,
            Capability::CAP_DAC_OVERRIDE => caps::Capability::CAP_DAC_OVERRIDE,
            Capability::CAP_DAC_READ_SEARCH => caps::Capability::CAP_DAC_READ_SEARCH,
            Capability::CAP_FOWNER => caps::Capability::CAP_FOWNER,
            Capability::CAP_FSETID => caps::Capability::CAP_FSETID,
            Capability::CAP_KILL => caps::Capability::CAP_KILL,
            Capability::CAP_SETGID => caps::Capability::CAP_SETGID,
            Capability::CAP_SETUID => caps::Capability::CAP_SETUID,
            Capability::CAP_SETPCAP => caps::Capability::CAP_SETPCAP,
            Capability::CAP_LINUX_IMMUTABLE => caps::Capability::CAP_LINUX_IMMUTABLE,
            Capability::CAP_NET_BIND_SERVICE => caps::Capability::CAP_NET_BIND_SERVICE,
            Capability::CAP_NET_BROADCAST => caps::Capability::CAP_NET_BROADCAST,
            Capability::CAP_NET_ADMIN => caps::Capability::CAP_NET_ADMIN,
            Capability::CAP_NET_RAW => caps::Capability::CAP_NET_RAW,
            Capability::CAP_IPC_LOCK => caps::Capability::CAP_IPC_LOCK,
            Capability::CAP_IPC_OWNER => caps::Capability::CAP_IPC_OWNER,
            Capability::CAP_SYS_MODULE => caps::Capability::CAP_SYS_MODULE,
            Capability::CAP_SYS_RAWIO => caps::Capability::CAP_SYS_RAWIO,
            Capability::CAP_SYS_CHROOT => caps::Capability::CAP_SYS_CHROOT,
            Capability::CAP_SYS_PTRACE => caps::Capability::CAP_SYS_PTRACE,
            Capability::CAP_SYS_PACCT => caps::Capability::CAP_SYS_PACCT,
            Capability::CAP_SYS_ADMIN => caps::Capability::CAP_SYS_ADMIN,
            Capability::CAP_SYS_BOOT => caps::Capability::CAP_SYS_BOOT,
            Capability::CAP_SYS_NICE => caps::Capability::CAP_SYS_NICE,
            Capability::CAP_SYS_RESOURCE => caps::Capability::CAP_SYS_RESOURCE,
            Capability::CAP_SYS_TIME => caps::Capability::CAP_SYS_TIME,
            Capability::CAP_SYS_TTY_CONFIG => caps::Capability::CAP_SYS_TTY_CONFIG,
            Capability::CAP_MKNOD => caps::Capability::CAP_MKNOD,
            Capability::CAP_LEASE => caps::Capability::CAP_LEASE,
            Capability::CAP_AUDIT_WRITE => caps::Capability::CAP_AUDIT_WRITE,
            Capability::CAP_AUDIT_CONTROL => caps::Capability::CAP_AUDIT_CONTROL,
            Capability::CAP_SETFCAP => caps::Capability::CAP_SETFCAP,
            Capability::CAP_MAC_OVERRIDE => caps::Capability::CAP_MAC_OVERRIDE,
            Capability::CAP_MAC_ADMIN => caps::Capability::CAP_MAC_ADMIN,
            Capability::CAP_SYSLOG => caps::Capability::CAP_SYSLOG,
            Capability::CAP_WAKE_ALARM => caps::Capability::CAP_WAKE_ALARM,
            Capability::CAP_BLOCK_SUSPEND => caps::Capability::CAP_BLOCK_SUSPEND,
            Capability::CAP_AUDIT_READ => caps::Capability::CAP_AUDIT_READ,
            Capability::CAP_PERFMON => caps::Capability::CAP_PERFMON,
            Capability::CAP_BPF => caps::Capability::CAP_BPF,
            Capability::CAP_CHECKPOINT_RESTORE => caps::Capability::CAP_CHECKPOINT_RESTORE,
        }
    }
}
