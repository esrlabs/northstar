use crate::{
    common::{container::Container, non_nul_string::NonNulString},
    debug, info,
    npk::manifest::{Capability, RLimitResource, RLimitValue},
    runtime::{
        fork::util::{self, fork, set_child_subreaper, set_log_target, set_process_name},
        ipc::{owned_fd::OwnedFd, raw_fd_ext::RawFdExt, Message as IpcMessage},
        ExitStatus, Pid,
    },
    seccomp::AllowList,
};
pub use builder::build;
use byteorder::ReadBytesExt;
use itertools::Itertools;
use nix::{
    errno::Errno,
    libc::{self, c_ulong, SIGCHLD},
    mount::MsFlags,
    sched::unshare,
    sys::{
        select,
        signal::Signal,
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd,
    unistd::Uid,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    env,
    ffi::CString,
    os::unix::{
        net::UnixStream,
        prelude::{AsRawFd, RawFd},
    },
    path::PathBuf,
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
        setsid: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Init {
    pub container: Container,
    pub root: PathBuf,
    pub uid: u16,
    pub gid: u16,
    pub mounts: Vec<Mount>,
    pub groups: Vec<u32>,
    pub capabilities: HashSet<Capability>,
    pub rlimits: HashMap<RLimitResource, RLimitValue>,
    pub seccomp: Option<AllowList>,
    pub console: bool,
}

/// Registers SIGCHLD handler and returns a socket that receives the notifications
fn register_sigchld_handler() -> std::io::Result<UnixStream> {
    let (write, read) = UnixStream::pair()?;
    write.set_cloexec(true)?;
    read.set_cloexec(true)?;

    unsafe {
        signal_hook::low_level::register(SIGCHLD, move || {
            unistd::write(write.as_raw_fd(), &[b'0'])
                .expect("failed to write byte into signal socket");
        })?;
    }

    Ok(read)
}

impl Init {
    pub fn run(self, mut stream: IpcMessage<UnixStream>, console: Option<OwnedFd>) -> ! {
        set_log_target(format!("northstar::init::{}", self.container));

        // Become a subreaper
        set_child_subreaper(true);

        // Set the process name to init. This process inherited the process name
        // from the runtime
        set_process_name(&format!("init-{}", self.container));

        // Become a session group leader
        debug!("Setting session id");
        unistd::setsid().expect("failed to call setsid");

        // Enter mount namespace
        debug!("Entering mount namespace");
        unshare(nix::sched::CloneFlags::CLONE_NEWNS).expect("failed to unshare NEWNS");

        // Perform all mounts passed in mounts
        self.mount();

        // Set the chroot to the containers root mount point
        debug!("Chrooting to {}", self.root.display());
        unistd::chroot(&self.root).expect("failed to chroot");

        // Set current working directory to root
        debug!("Setting current working directory to root");
        env::set_current_dir("/").expect("failed to set cwd to /");

        // UID / GID
        self.set_ids();

        // Supplementary groups
        self.set_groups();

        // Apply resource limits
        self.set_rlimits();

        // No new privileges
        Self::set_no_new_privs(true);

        // Capabilities
        self.drop_privileges();

        // Set SIGCHLD signal handler
        let mut signals = register_sigchld_handler().expect("failed to register signal handler");

        let signals_fd = signals.as_raw_fd();
        let forker_fd = stream.as_raw_fd();

        loop {
            let mut fd_set = select::FdSet::new();
            fd_set.insert(forker_fd);
            fd_set.insert(signals_fd);

            match select::select(None, &mut fd_set, None, None, None) {
                Ok(_) => {}
                Err(Errno::EINTR) => {
                    // Signal was caught
                    continue;
                }
                Err(e) => {
                    panic!("Failed to select: {}", e);
                }
            }

            // Received an exec request from forker
            if fd_set.contains(forker_fd) {
                let (path, args, mut env, setsid) = match stream.recv() {
                    Ok(Some(Message::Exec {
                        path,
                        args,
                        env,
                        setsid,
                    })) => (path, args, env, setsid),
                    Ok(None) => {
                        info!("Channel closed. Exiting...");
                        std::process::exit(0);
                    }
                    Ok(Some(msg)) => panic!("unexpected message: {:?}", msg),
                    Err(e) => panic!("failed to receive message: {}", e),
                };
                debug!("Execing {} {}", path, args.iter().join(" "));

                // The init process got adopted by the forker after the trampoline exited. It is
                // safe to set the parent death signal now.
                util::set_parent_death_signal(Signal::SIGKILL);

                if let Some(fd) = console.as_ref().map(AsRawFd::as_raw_fd) {
                    // Add the fd number to the environment of the application
                    let console_env = format!("NORTHSTAR_CONSOLE={}", fd);
                    // Safety: `console_env` is a valid UTF-8 string
                    env.push(unsafe { NonNulString::from_string_unchecked(console_env) });
                }

                let io = stream.recv_fds::<RawFd, 3>().expect("failed to receive io");
                debug_assert!(io.len() == 3);
                let stdin = io[0];
                let stdout = io[1];
                let stderr = io[2];

                // Start new process inside the container
                let pid = fork(|| {
                    set_log_target(format!("northstar::{}", self.container));
                    util::set_parent_death_signal(Signal::SIGKILL);

                    if setsid {
                        unistd::setsid().expect("failed to call setsid");
                        if unsafe { nix::libc::ioctl(stdin.as_raw_fd(), nix::libc::TIOCSCTTY) } < 0
                        {
                            panic!("Failed to TIOCSCTTY");
                        }
                    }

                    unistd::dup2(stdin, nix::libc::STDIN_FILENO).expect("failed to dup2");
                    unistd::dup2(stdout, nix::libc::STDOUT_FILENO).expect("failed to dup2");
                    unistd::dup2(stderr, nix::libc::STDERR_FILENO).expect("failed to dup2");

                    unistd::close(stdin).expect("failed to close stdout");
                    unistd::close(stdout).expect("failed to close stdout");
                    unistd::close(stderr).expect("failed to close stderr");

                    // Set seccomp filter
                    if let Some(ref filter) = self.seccomp {
                        filter.apply().expect("failed to apply seccomp filter.");
                    }

                    let path = CString::from(path);
                    let args = args.into_iter().map_into::<CString>().collect_vec();
                    let env = env.into_iter().map_into::<CString>().collect_vec();

                    panic!(
                        "execve: {:?} {:?}: {:?}",
                        &path,
                        &args,
                        unistd::execve(&path, &args, &env)
                    )
                })
                .expect("failed to spawn child process");

                unistd::close(stdin).expect("failed to close stdout");
                unistd::close(stdout).expect("failed to close stdout");
                unistd::close(stderr).expect("failed to close stderr");

                let message = Message::Forked { pid };
                stream.send(&message).expect("failed to send fork result");
            }

            // Reap child process
            if fd_set.contains(signals_fd) {
                signals
                    .read_u8()
                    .expect("failed to read byte from signal socket");

                loop {
                    let (pid, exit_status) = match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                        Ok(WaitStatus::Exited(pid, status)) => {
                            (pid.as_raw() as u32, ExitStatus::Exit(status))
                        }
                        Ok(WaitStatus::Signaled(pid, status, _)) => {
                            (pid.as_raw() as u32, ExitStatus::Signalled(status as u8))
                        }
                        Ok(WaitStatus::StillAlive) => break,
                        Err(Errno::ECHILD) => {
                            // No more processes to wait for
                            std::process::exit(0);
                        }
                        Ok(WaitStatus::Continued(_)) | Ok(WaitStatus::Stopped(_, _)) => continue,
                        e => panic!("Failed to waitpid: {:?}", e),
                    };

                    stream
                        .send(Message::Exit { pid, exit_status })
                        .expect("failed to send exit message");
                }
            }
        }
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
        flags: MsFlags,
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
            // Safe because flags is private and only set in Mount::new via MsFlags::bits
            unsafe { MsFlags::from_bits_unchecked(self.flags) },
            self.data.as_deref(),
        )
        .expect(&self.error_msg);
    }
}
