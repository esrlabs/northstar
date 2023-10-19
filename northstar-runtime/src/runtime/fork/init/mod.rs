use crate::{
    common::{container::Container, non_nul_string::NonNulString},
    npk::manifest::{
        capabilities::Capability,
        network::Network,
        rlimit::{RLimitResource, RLimitValue},
        sched::{Policy, Sched},
        selinux::Selinux,
    },
    runtime::{
        exit_status::ExitStatus,
        fork::util::{self, set_child_subreaper, set_process_name},
        ipc::FramedUnixStream,
        runtime::Pid,
    },
    seccomp::AllowList,
};
pub use builder::build;
use itertools::Itertools;
use log::{debug, info, warn};
use nix::{
    errno::Errno,
    fcntl::{self},
    libc::{self, c_ulong},
    mount::{self},
    sched::{self, unshare, CloneFlags},
    sys::{
        signal::Signal,
        stat::Mode,
        wait::{waitpid, WaitStatus},
    },
    unistd::{self, fork, ForkResult, Uid},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    env,
    ffi::{c_int, CString},
    fs,
    io::{self, Write},
    os::unix::prelude::{AsRawFd, OwnedFd},
    path::{Path, PathBuf},
    process::exit,
};

mod builder;

// Message from the forker to init and response
#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    /// The init process forked a new child with `pid`
    Forked { pid: Pid },
    /// A child of init exited with `exit_status`
    Exit { pid: Pid, exit_status: ExitStatus },
    /// Exec a new process
    Exec {
        path: NonNulString,
        args: Vec<NonNulString>,
        env: Vec<NonNulString>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Init {
    pub container: Container,
    pub root: PathBuf,
    pub uid: u16,
    pub gid: u16,
    pub sched: Option<Sched>,
    pub mounts: Vec<Mount>,
    pub groups: Vec<u32>,
    pub network: Option<Network>,
    pub capabilities: HashSet<Capability>,
    pub rlimits: HashMap<RLimitResource, RLimitValue>,
    pub seccomp: Option<AllowList>,
    pub console: bool,
    pub sockets: Vec<String>,
    pub selinux: Option<Selinux>,
}

impl Init {
    pub fn run(
        self,
        mut stream: FramedUnixStream,
        console: Option<OwnedFd>,
        sockets: Vec<OwnedFd>,
    ) -> ! {
        let (path, args, env) = match stream.recv() {
            Ok(Some(Message::Exec { path, args, env })) => (path, args, env),
            Ok(None) => {
                info!("Channel closed. Exiting...");
                std::process::exit(0);
            }
            Ok(_) => unreachable!("unimplemented message"),
            Err(e) => panic!("failed to receive message: {e}"),
        };

        // Become a subreaper
        set_child_subreaper(true);

        // SE context transition
        if let Some(context) = self.selinux.as_ref().and_then(|s| s.exec.as_ref()) {
            debug!("Setting SELinux context to {}", context);
            let mut exec = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/proc/thread-self/attr/exec")
                .expect("failed to open SELinux context file");
            exec.write_all(context.as_bytes())
                .expect("failed to write SELinux context");
        }

        // Set the process name to init. This process inherited the process name
        // from the runtime
        set_process_name(&format!("init-{}", self.container));

        // Apply scheduler settings
        //self.set_scheduler();

        // Become a session group leader
        debug!("Setting session id");
        unistd::setsid().expect("failed to call setsid");

        // Enter network namespace
        self.network();

        // Enter mount namespace
        debug!("Entering mount, IPC and UTS namespace");
        sched::unshare(
            CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWIPC | CloneFlags::CLONE_NEWUTS,
        )
        .expect("failed to unshare");

        // Perform all mounts passed in mounts
        self.mount();

        // Set the root to the containers root mount point
        self.pivot_rootfs(&self.root);

        // Set current working directory to root
        debug!("Setting current working directory to root");
        env::set_current_dir("/").expect("failed to set cwd to /");

        // UID / GID
        self.set_ids();

        // Supplementary groups
        self.set_groups();

        // Apply resource limits
        self.set_rlimits();

        // The init process got adopted by the forker after the trampoline exited. It is
        // safe to set the parent death signal now.
        util::set_parent_death_signal(Signal::SIGKILL);

        let path = CString::from(path);
        let args: Vec<_> = args.into_iter().map_into::<CString>().collect();
        let env: Vec<_> = {
            let env = env.into_iter().map_into::<CString>();

            // Console fd env variable (if present).
            let console = console
                .as_ref()
                .map(AsRawFd::as_raw_fd)
                .map(|fd| format!("NORTHSTAR_CONSOLE={fd}"))
                .map(|var| unsafe { NonNulString::from_string_unchecked(var) })
                .into_iter()
                .map(Into::into);

            // Set socket env variables.
            let sockets = self.sockets.iter().zip(&sockets).map(|(name, fd)| {
                let fd = fd.as_raw_fd();
                let var = format!("NORTHSTAR_SOCKET_{name}={fd}");
                let var = unsafe { NonNulString::from_string_unchecked(var) };
                var.into()
            });

            env.chain(console).chain(sockets).collect()
        };

        // Start new process inside the container
        let pid = match unsafe { fork().expect("failed to fork") } {
            ForkResult::Parent { child } => child.as_raw() as Pid,
            ForkResult::Child => {
                util::set_parent_death_signal(Signal::SIGKILL);

                // Apply scheduling parameters. The parameters shall not be applied to
                // the init process and therefore this is done *after* fork.
                self.set_scheduler_policy()
                    .expect("failed to set scheduler policy");

                // Set seccomp filter
                if let Some(ref filter) = self.seccomp {
                    filter.apply().expect("failed to apply seccomp filter.");
                }

                // No new privileges
                Self::set_no_new_privs(true);

                // Capabilities
                self.drop_privileges();

                panic!(
                    "execve: {:?} {:?}: {:?}",
                    &path,
                    &args,
                    unistd::execve(&path, &args, &env)
                )
            }
        };

        // Close the console fd. Used in the container binary only.
        drop(console);

        // Close sockets in init.
        drop(sockets);

        // Free some memory.
        drop((path, args, env));

        // Inform the forker that we forked.
        stream
            .send(&Message::Forked { pid })
            .expect("failed to send fork result");

        // Wait for the child to exit
        let exit_status = loop {
            debug!("Waiting for child process {} to exit", pid);
            match waitpid(Some(unistd::Pid::from_raw(pid as i32)), None) {
                Ok(WaitStatus::Exited(_, status)) => {
                    debug!("Child process {} exited with status code {}", pid, status);
                    break ExitStatus::Exit(status);
                }
                Ok(WaitStatus::Signaled(_, status, _)) => {
                    debug!("Child process {} exited with signal {}", pid, status);
                    break ExitStatus::Signalled(status as u8);
                }
                Ok(WaitStatus::Continued(_)) | Ok(WaitStatus::Stopped(_, _)) => {
                    log::warn!("Child process continued or stopped");
                    continue;
                }
                Err(nix::Error::EINTR) => continue,
                e => panic!("failed to waitpid on {pid}: {e:?}"),
            }
        };

        stream
            .send(Message::Exit { pid, exit_status })
            .expect("channel error");

        exit(0);
    }

    /// Set uid/gid
    fn set_ids(&self) {
        let uid = self.uid;
        let gid = self.gid;

        let rt_privileged = unistd::geteuid() == Uid::from_raw(0);

        // If running as uid 0 save our caps across the uid/gid drop
        if rt_privileged {
            caps::securebits::set_keepcaps(true).expect("failed to set keep caps");
        }

        debug!("Setting resgid {}", gid);
        let gid = unistd::Gid::from_raw(gid.into());
        unistd::setresgid(gid, gid, gid).expect("failed to set resgid");

        let uid = unistd::Uid::from_raw(uid.into());
        debug!("Setting resuid {}", uid);
        unistd::setresuid(uid, uid, uid).expect("failed to set resuid");

        if rt_privileged {
            self.reset_effective_caps();
            caps::securebits::set_keepcaps(false).expect("failed to set keep caps");
        }
    }

    fn set_groups(&self) {
        debug!("Setting groups {:?}", self.groups);
        let result = unsafe { nix::libc::setgroups(self.groups.len(), self.groups.as_ptr()) };

        Errno::result(result)
            .map(drop)
            .expect("failed to set supplementary groups");
    }

    fn set_rlimits(&self) {
        debug!("Applying rlimits");
        for (resource, limit) in &self.rlimits {
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
                .expect("failed to set rlimit");
        }
    }

    /// Drop capabilities
    fn drop_privileges(&self) {
        debug!("Dropping priviledges");
        let mut bounded =
            caps::read(None, caps::CapSet::Bounding).expect("failed to read bounding caps");
        // Convert the set from the manifest to a set of caps::Capability
        let set = self
            .capabilities
            .iter()
            .cloned()
            .map(Into::into)
            .collect::<HashSet<caps::Capability>>();
        bounded.retain(|c| !set.contains(c));

        for cap in &bounded {
            // caps::set cannot be called for bounded
            caps::drop(None, caps::CapSet::Bounding, *cap).expect("failed to drop bounding cap");
        }
        caps::set(None, caps::CapSet::Effective, &set).expect("failed to set effective caps");
        caps::set(None, caps::CapSet::Permitted, &set).expect("failed to set permitted caps");
        caps::set(None, caps::CapSet::Inheritable, &set).expect("failed to set inheritable caps");
        caps::set(None, caps::CapSet::Ambient, &set).expect("failed to set ambient caps");
    }

    // Reset effective caps to the most possible set
    fn reset_effective_caps(&self) {
        let all = caps::all();
        caps::set(None, caps::CapSet::Effective, &all).expect("failed to reset effective caps");
    }

    /// Execute list of mount calls
    fn mount(&self) {
        for mount in &self.mounts {
            mount.mount();
        }
    }

    fn set_no_new_privs(value: bool) {
        #[cfg(target_os = "android")]
        pub const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
        #[cfg(not(target_os = "android"))]
        use libc::PR_SET_NO_NEW_PRIVS;

        debug!("Setting no new privs");
        let result = unsafe { nix::libc::prctl(PR_SET_NO_NEW_PRIVS, value as c_ulong, 0, 0, 0) };
        Errno::result(result)
            .map(drop)
            .expect("failed to set PR_SET_NO_NEW_PRIVS")
    }

    fn network(&self) {
        match &self.network {
            Some(Network::Host) => {
                debug!("Using host network");
            }
            Some(Network::Namespace(namespace)) => {
                #[cfg(target_os = "android")]
                let path = Path::new("/run/netns").join(namespace);
                #[cfg(not(target_os = "android"))]
                let path = Path::new("/var/run/netns").join(namespace);

                if path.exists() {
                    let handle = fs::OpenOptions::new()
                        .read(true)
                        .write(false)
                        .open(&path)
                        .expect("failed to open netns");
                    debug!("Trying to attach to network namespace \"{}\"", namespace);
                    sched::setns(handle, CloneFlags::CLONE_NEWNET).expect("failed to enter netns");
                } else {
                    warn!("Failed to attach to network namespace \"{}\"", namespace);
                }
            }
            None => {
                debug!("Unsharing network namespace");
                unshare(CloneFlags::CLONE_NEWNET).expect("failed to unshare");
            }
        }
    }

    /// Set the rootfs to `path`. Thanks to the `youki` project where this code borrowed from.
    /// https://github.com/containers/youki.
    fn pivot_rootfs(&self, path: &Path) {
        debug!("Pivot rooting to {}", self.root.display());

        // Open the path as directory and read only
        let newroot = fcntl::open(
            path,
            fcntl::OFlag::O_DIRECTORY | fcntl::OFlag::O_RDONLY,
            Mode::empty(),
        )
        .expect("failed to open new root");

        // Make the given path as the root directory for the container
        // see https://man7.org/linux/man-pages/man2/pivot_root.2.html, specially the notes
        // pivot root usually changes the root directory to first argument, and then mounts the original root
        // directory at second argument. Giving same path for both stacks mapping of the original root directory
        // above the new directory at the same path, then the call to umount unmounts the original root directory from
        // this path. This is done, as otherwise, we will need to create a separate temporary directory under the new root path
        // so we can move the original root there, and then unmount that. This way saves the creation of the temporary
        // directory to put original root directory.
        unistd::pivot_root(path, path).expect("failed to set pivot root");

        // Make the original root directory rslave to avoid propagating unmount event to the host mount namespace.
        // We should use MS_SLAVE not MS_PRIVATE according to https://github.com/opencontainers/runc/pull/1500.
        mount::mount(
            None::<&str>,
            "/",
            None::<&str>,
            mount::MsFlags::MS_SLAVE | mount::MsFlags::MS_REC,
            None::<&str>,
        )
        .expect("failed to mount");

        // Unmount the original root directory which was stacked on top of new root directory
        // MNT_DETACH makes the mount point unavailable to new accesses, but waits till the original mount point
        // to be free of activity to actually unmount
        // see https://man7.org/linux/man-pages/man2/umount2.2.html for more information
        mount::umount2("/", mount::MntFlags::MNT_DETACH).expect("failed to umount old root");

        // Change directory to root
        unistd::fchdir(newroot).expect("failed to fchdir");
        unistd::close(newroot).expect("failed to close");
    }

    /// Set the scheduling policy.
    fn set_scheduler_policy(&self) -> io::Result<()> {
        let policy = if let Some(ref sched) = self.sched {
            &sched.policy
        } else {
            return Ok(());
        };

        #[inline]
        fn set_scheduler(policy: c_int, priority: c_int) -> io::Result<()> {
            #[cfg(not(target_env = "musl"))]
            let params = libc::sched_param {
                sched_priority: priority,
            };
            #[cfg(target_env = "musl")]
            let params = libc::sched_param {
                sched_priority: priority,
                sched_ss_low_priority: 0,
                sched_ss_repl_period: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                sched_ss_init_budget: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                sched_ss_max_repl: 0,
            };

            let params_ptr: *const libc::sched_param = &params;

            match unsafe { libc::sched_setscheduler(0, policy, params_ptr) } {
                0 => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }

        /// Renice a process.
        #[inline]
        fn nice(nice: i32) -> io::Result<()> {
            match unsafe { libc::nice(nice) } {
                0 => Ok(()),
                _ => Err(io::Error::last_os_error()),
            }
        }

        /// Does not exist in libc yet for some reason.
        const SCHED_DEADLINE: c_int = 6;

        #[cfg(target_os = "android")]
        const SCHED_OTHER: libc::c_int = libc::SCHED_NORMAL;
        #[cfg(not(target_os = "android"))]
        use libc::SCHED_OTHER;

        match policy {
            Policy::Other { nice: n } => {
                set_scheduler(SCHED_OTHER, 0)?;
                nice(*n as i32)
            }
            Policy::Fifo { priority } => set_scheduler(libc::SCHED_FIFO, *priority as c_int),
            Policy::Batch { nice: n } => {
                set_scheduler(libc::SCHED_BATCH, 0)?;
                nice(*n as i32)
            }
            Policy::RoundRobin { priority } => set_scheduler(libc::SCHED_RR, *priority as c_int),
            Policy::Idle => set_scheduler(libc::SCHED_IDLE, 0),
            Policy::Deadline => set_scheduler(SCHED_DEADLINE, 0),
        }
    }
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

/// Instructions for mount system call done in init
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mount {
    pub source: Option<PathBuf>,
    pub target: PathBuf,
    pub fstype: Option<String>,
    pub flags: u64,
    pub data: Option<String>,
    pub error_msg: String,
}

impl Mount {
    pub fn new(
        source: Option<PathBuf>,
        target: PathBuf,
        fstype: Option<&'static str>,
        flags: mount::MsFlags,
        data: Option<String>,
    ) -> Mount {
        let error_msg = format!(
            "failed to mount '{}' of type '{}' on '{}' with flags '{:?}' and data '{}'",
            source.clone().unwrap_or_default().display(),
            fstype.unwrap_or_default(),
            target.display(),
            flags,
            data.clone().unwrap_or_default()
        );
        Mount {
            source,
            target,
            fstype: fstype.map(|s| s.to_string()),
            flags: flags.bits(),
            data,
            error_msg,
        }
    }

    /// Execute this mount call
    pub(super) fn mount(&self) {
        nix::mount::mount(
            self.source.as_ref(),
            &self.target,
            self.fstype.as_deref(),
            mount::MsFlags::from_bits_truncate(self.flags),
            self.data.as_deref(),
        )
        .expect(&self.error_msg);
    }
}
