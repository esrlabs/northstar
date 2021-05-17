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
    clone::clone, io::Fd, utils::PathExt, Container, IslandProcess, ENV_NAME, ENV_VERSION,
    SIGNAL_OFFSET,
};
use crate::runtime::{
    config::Config,
    pipe::{Condition, ConditionNotify, ConditionWait},
};
use log::{debug, warn};
use nix::{
    errno::Errno,
    libc::{self, c_int, c_ulong, pid_t, siginfo_t},
    mount::MsFlags,
    sched,
    sys::{
        self,
        signal::{
            sigaction, signal, sigprocmask, SaFlags, SigAction, SigHandler, SigSet, SigmaskHow,
            Signal, SIGCHLD, SIGKILL,
        },
    },
    unistd::{self, Uid},
};
use npk::manifest::{Manifest, MountFlag};
use sched::CloneFlags;
use std::{
    collections::HashSet,
    env,
    ffi::{c_void, CString},
    os::unix::prelude::RawFd,
    path::PathBuf,
    process::exit,
    ptr::null,
};
use sys::wait::{waitpid, WaitStatus};
use tokio::task;

static mut CHILD_PID: pid_t = -1;

#[derive(Debug)]
pub(super) struct Mount {
    source: Option<PathBuf>,
    target: PathBuf,
    fstype: Option<&'static str>,
    flags: MsFlags,
    data: Option<String>,
}

/// Prepare a list of mounts that can be done in init without any allocation.
pub(super) async fn mounts(
    config: &Config,
    container: &Container<IslandProcess>,
) -> Result<Vec<Mount>, super::Error> {
    let mut mounts = Vec::new();
    let root = container
        .root
        .canonicalize()
        .map_err(|e| super::Error::io("Canonicalize root", e))?;
    let uid = container.manifest.uid;
    let gid = container.manifest.gid;

    // /proc
    debug!("Mounting /proc");
    let target = root.join("proc");
    mounts.push(Mount {
        source: Some(PathBuf::from("proc")),
        target: target.clone(),
        fstype: Some("proc"),
        flags: MsFlags::empty(),
        data: None,
    });
    // Remount /proc ro
    debug!("Remount /proc read only");
    let flags = MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
    mounts.push(Mount {
        source: Some(PathBuf::from("/proc")),
        target,
        fstype: None,
        flags,
        data: None,
    });

    // TODO: /dev
    mounts.push(Mount {
        source: Some(PathBuf::from("/dev")),
        target: root.join("dev"),
        fstype: None,
        flags: MsFlags::MS_BIND,
        data: None,
    });

    for (target, mount) in &container.manifest.mounts {
        match &mount {
            npk::manifest::Mount::Bind { host, flags } => {
                if !&host.exists() {
                    debug!(
                        "Skipping bind mount of nonexitent source {} to {}",
                        host.display(),
                        target.display()
                    );
                    continue;
                }
                let rw = flags.contains(&MountFlag::Rw);
                debug!(
                    "Mounting {} on {}{}",
                    host.display(),
                    target.display(),
                    if rw { " (rw)" } else { "" }
                );
                let target = root.join_strip(target);
                mounts.push(Mount {
                    source: Some(host.clone()),
                    target: target.clone(),
                    fstype: None,
                    flags: MsFlags::MS_BIND | MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
                    data: None,
                });

                if !rw {
                    mounts.push(Mount {
                        source: Some(host.clone()),
                        target,
                        fstype: None,
                        flags: MsFlags::MS_BIND
                            | MsFlags::MS_REMOUNT
                            | MsFlags::MS_RDONLY
                            | MsFlags::MS_NODEV
                            | MsFlags::MS_NOSUID,
                        data: None,
                    });
                }
            }
            npk::manifest::Mount::Persist => {
                let dir = config.data_dir.join(&container.manifest.name);
                if !dir.exists() {
                    debug!("Creating {}", dir.display());
                    tokio::fs::create_dir_all(&dir).await.map_err(|e| {
                        super::Error::Io(format!("Failed to create {}", dir.display()), e)
                    })?;
                }

                debug!("Chowning {} to {}:{}", dir.display(), uid, gid);
                task::block_in_place(|| {
                    unistd::chown(
                        dir.as_os_str(),
                        Some(unistd::Uid::from_raw(uid)),
                        Some(unistd::Gid::from_raw(gid)),
                    )
                })
                .map_err(|e| {
                    super::Error::os(
                        format!("Failed to chown {} to {}:{}", dir.display(), uid, gid),
                        e,
                    )
                })?;

                debug!("Mounting {} on {}", dir.display(), target.display(),);

                mounts.push(Mount {
                    source: Some(dir),
                    target: root.join_strip(target),
                    fstype: None,
                    flags: MsFlags::MS_BIND
                        | MsFlags::MS_NODEV
                        | MsFlags::MS_NOSUID
                        | MsFlags::MS_NOEXEC,
                    data: None,
                });
            }
            npk::manifest::Mount::Resource { name, version, dir } => {
                let src = {
                    // Join the source of the resource container with the mount dir
                    let resource_root = config.run_dir.join(format!("{}:{}", name, version));
                    let dir = dir
                        .strip_prefix("/")
                        .map(|d| resource_root.join(d))
                        .unwrap_or(resource_root);

                    if !dir.exists() {
                        return Err(super::Error::StartContainerMissingResource(
                            container.container.clone(),
                            container.container.clone(),
                        ));
                    }

                    dir
                };

                debug!("Mounting {} on {}", src.display(), target.display());

                let target = root.join_strip(target);
                mounts.push(Mount {
                    source: Some(src.clone()),
                    target: target.clone(),
                    fstype: None,
                    flags: MsFlags::MS_BIND | MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
                    data: None,
                });

                // Remount ro
                mounts.push(Mount {
                    source: Some(src),
                    target,
                    fstype: None,
                    flags: MsFlags::MS_BIND
                        | MsFlags::MS_REMOUNT
                        | MsFlags::MS_RDONLY
                        | MsFlags::MS_NODEV,
                    data: None,
                });
            }
            npk::manifest::Mount::Tmpfs { size } => {
                debug!(
                    "Mounting tmpfs with size {} on {}",
                    bytesize::ByteSize::b(*size),
                    target.display()
                );
                mounts.push(Mount {
                    source: None,
                    target: root.join_strip(target),
                    fstype: Some("tmpfs"),
                    flags: MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
                    data: Some(format!("size={},mode=1777", size)),
                });
            }
            npk::manifest::Mount::Dev { .. } => { /* See above */ }
        }
    }

    Ok(mounts)
}

/// Generate a list of supplementary gids if the groups info can be retrieved. This
/// must happen before the init `clone` because the group information cannot be gathered
/// without `/etc` etc...
pub(super) fn groups(manifest: &Manifest) -> Vec<u32> {
    if let Some(groups) = manifest.suppl_groups.as_ref() {
        let mut result = Vec::with_capacity(groups.len());
        for group in groups {
            let cgroup = CString::new(group.as_str()).unwrap(); // Check during manifest parsing
            let group_info = task::block_in_place(|| unsafe {
                nix::libc::getgrnam(cgroup.as_ptr() as *const nix::libc::c_char)
            });
            if group_info == (null::<c_void>() as *mut nix::libc::group) {
                warn!("Skipping invalid supplementary group {}", group);
            } else {
                let gid = unsafe { (*group_info).gr_gid };
                // TODO: Are there gids cannot use?
                result.push(gid)
            }
        }
        result
    } else {
        Vec::with_capacity(0)
    }
}

pub(super) fn args(manifest: &npk::manifest::Manifest) -> (CString, Vec<CString>, Vec<CString>) {
    let init = CString::new(manifest.init.as_ref().unwrap().to_str().unwrap()).unwrap();
    let mut argv = vec![init.clone()];
    if let Some(ref args) = manifest.args {
        for arg in args {
            argv.push(CString::new(arg.as_bytes()).unwrap());
        }
    }

    let mut env = manifest.env.clone().unwrap_or_default();
    env.insert(ENV_NAME.to_string(), manifest.name.to_string());
    env.insert(ENV_VERSION.to_string(), manifest.version.to_string());
    let env = env
        .iter()
        .map(|(k, v)| CString::new(format!("{}={}", k, v)))
        .map(Result::unwrap)
        .collect::<Vec<CString>>();

    (init, argv, env)
}

// Init function. Pid 1.
#[allow(clippy::too_many_arguments)]
pub(super) fn init(
    container: &Container<IslandProcess>,
    init: &CString,
    argv: &[CString],
    env: &[CString],
    mounts: &[Mount],
    fds: &[(RawFd, Fd)],
    groups: &[u32],
    cond_cloned_notify: ConditionNotify,
    cond_start_wait: ConditionWait,
    cond_started_notify: ConditionNotify,
) -> ! {
    pr_set_name_init();

    // Install signal handlers that forward every signal to our child
    init_signal_handlers();

    // Become a subreaper for orphans in this namespace
    set_child_subreaper(true);

    let manifest = &container.manifest;
    let root = container
        .root
        .canonicalize()
        .expect("Failed to canonicalize root");

    // Mount
    mount(&mounts);

    // Chroot
    unistd::chroot(&root).expect("Failed to chroot");

    // Pwd
    env::set_current_dir("/").expect("Failed to set cwd to /");

    // UID / GID
    setid(manifest.uid, manifest.gid);

    // Supplementary groups
    setgroups(groups);

    //println!("Setting no new privs");
    set_no_new_privs(true);

    // Set the parent process death signal of the calling process to arg2
    // (either a signal value in the range 1..maxsig, or 0 to clear).
    //println!("Setting parent death signal to SIGKILL");
    //set_parent_death_signal(SIGKILL);

    // Capabilities
    drop_capabilities(manifest.capabilities.as_ref());

    // Close and dup fds
    file_descriptors(fds);

    // Setting the parent death signal *must* be done *after* changing uid/gid which clear this flag.
    // TODO: Fix the "we're spawned from a thread that times out" issue
    //set_parent_death_signal(SIGKILL);

    let cond_cloned = Condition::new().expect("Failed to create condition");

    match clone(
        CloneFlags::empty(),
        Some(SIGCHLD as i32),
        Some(unsafe { &mut (CHILD_PID) }),
    ) {
        Ok(result) => match result {
            unistd::ForkResult::Parent { child } => {
                assert_eq!(unsafe { CHILD_PID }, child.as_raw());

                // These conditions are handled in the child
                drop(cond_start_wait);
                drop(cond_started_notify);

                // Wait until the child signals that is has resetted it's signal handlers before
                // we signal to the runtime that the clone is done. This is important because the rt might
                // try to kill us before this happened.
                cond_cloned.wait();
                // Signal the runtime that the child is cloned
                cond_cloned_notify.notify();

                // Wait for the child to exit
                match waitpid(Some(child), None).expect("waitpid") {
                    WaitStatus::Exited(_pid, status) => exit(status),
                    WaitStatus::Signaled(_pid, status, _) => {
                        // Encode the signal number in the process exit status. It's not possible to raise a
                        // a signal in this "init" process that is received by our parent
                        let code = SIGNAL_OFFSET + status as i32;
                        //debug!("Exiting with {} (signaled {})", code, status);
                        exit(code);
                    }
                    // TODO: Other waitpid results
                    _ => panic!("abnormal exit of child process"),
                };
            }
            unistd::ForkResult::Child => {
                set_parent_death_signal(SIGKILL);

                // TODO: Post Linux 5.5 there's a nice clone flag that allows
                // to reset the signal handler during the clone.
                reset_signal_handlers();
                reset_signal_mask();

                // Signal init that we setup the signal handling
                drop(cond_cloned_notify);
                cond_cloned.notify();

                // Wait for the start command from the runtime
                cond_start_wait.wait();

                // Signal the runtime that we're started
                cond_started_notify.notify();

                // Set seccomp filter
                // TODO: Move the allocations to parent/parent
                set_seccomp_filter(container.manifest.seccomp.as_ref());

                panic!("{:?}", unistd::execve(&init, &argv, &env))
            }
        },
        Err(e) => panic!("Clone error: {}", e),
    }
}

// TODO: The container could be malformed and the mountpoint might be
// missing. This is not a fault of the RT so don't expect it.
// TODO: mount flags: nosuid etc....
// TODO: /dev mounts from manifest: full or minimal
fn mount(mounts: &[Mount]) {
    for mount in mounts {
        nix::mount::mount(
            mount.source.as_ref(),
            &mount.target,
            mount.fstype,
            mount.flags,
            mount.data.as_deref(),
        )
        .expect("Failed to mount");
    }
}

/// Apply file descriptor configuration
fn file_descriptors(map: &[(RawFd, Fd)]) {
    for (fd, value) in map {
        match value {
            Fd::Inherit => (),
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

/// Install a signal handler that forwards alls signals to the child process
/// Init processes by default have *no* signal handlers installed.
fn init_signal_handlers() {
    for sig in Signal::iterator()
        .filter(|s| *s != Signal::SIGCHLD)
        .filter(|s| *s != Signal::SIGKILL)
        .filter(|s| *s != Signal::SIGSTOP)
    {
        unsafe {
            let handler = SigHandler::SigAction(forward_signal_to_child);
            let action = SigAction::new(
                handler,
                SaFlags::SA_SIGINFO | SaFlags::SA_RESTART,
                SigSet::all(),
            );
            sigaction(sig, &action).expect("Failed to install sigaction");
        }
    }
}

extern "C" fn forward_signal_to_child(signal: c_int, _: *mut siginfo_t, _: *mut c_void) {
    let child_pid = unsafe { CHILD_PID };
    if child_pid != -1 {
        // Writing to stdout in signal handler is bad. Just left this here
        // for printlnging.
        //println!("{}: forwarding {} to {}", std::process::id(), signal, child);
        unsafe { libc::kill(child_pid, signal) };
    } else {
        panic!("Internal error: child pid not set in signal handler");
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
        .expect("Failed to set PR_SET_PDEATHSIG");
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

fn set_seccomp_filter(filter: Option<&std::collections::HashMap<String, String>>) {
    if let Some(filter) = filter {
        let mut builder = super::seccomp::Builder::new();
        for syscall_name in filter.keys() {
            builder = builder.allow_syscall_name(syscall_name);
        }
        builder.apply();
    }
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

fn pr_set_name_init() {
    let cname = "init\0";
    let result = unsafe { libc::prctl(PR_SET_NAME, cname.as_ptr() as c_ulong, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .expect("Failed to set PR_SET_KEEPCAPS");
}

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

// Reset effective caps to the most possible set
fn reset_effective_caps() {
    //println!("Resetting effective capabilities");
    caps::set(None, caps::CapSet::Effective, &caps::all()).expect("Failed to reset effective caps");
}

/// Set uid/gid
fn setid(uid: u32, gid: u32) {
    let rt_priveleged = unistd::geteuid() == Uid::from_raw(0);

    // If running as uid 0 safe our caps across the uid/gid drop
    if rt_priveleged {
        caps::securebits::set_keepcaps(true).expect("Failed to set keep caps");
    }

    //println!("Setting gid to {}", gid);
    let gid = unistd::Gid::from_raw(gid);
    unistd::setresgid(gid, gid, gid).expect("Failed to set resgid");

    //println!("Setting uid to {}", uid);
    let uid = unistd::Uid::from_raw(uid);
    unistd::setresuid(uid, uid, uid).expect("Failed to set resuid");

    if rt_priveleged {
        reset_effective_caps();
        caps::securebits::set_keepcaps(false).expect("Failed to set keep caps");
    }
}

fn setgroups(groups: &[u32]) {
    //println!("Setting groups {:?}", groups);
    let result = unsafe { nix::libc::setgroups(groups.len(), groups.as_ptr()) };

    Errno::result(result)
        .map(drop)
        .expect("Failed to set PR_SET_PDEATHSIG");
}

/// Drop capabilities
fn drop_capabilities(cs: Option<&HashSet<caps::Capability>>) {
    let mut bounded =
        caps::read(None, caps::CapSet::Bounding).expect("Failed to read bouding caps");
    if let Some(caps) = cs {
        bounded.retain(|c| !caps.contains(c));
    }

    //println!("Dropping capabilities");
    for cap in bounded {
        // caps::set cannot be called for bounded
        caps::drop(None, caps::CapSet::Bounding, cap).expect("Failed to drop bounding cap");
    }

    if let Some(caps) = cs {
        //println!("Settings capabilities to {:?}", caps);
        caps::set(None, caps::CapSet::Effective, caps).expect("Failed to set effective caps");
        caps::set(None, caps::CapSet::Permitted, caps).expect("Failed to set permitted caps");
        caps::set(None, caps::CapSet::Inheritable, caps).expect("Failed to set inheritable caps");
        caps::set(None, caps::CapSet::Ambient, caps).expect("Failed to set ambient caps");
    }
}
