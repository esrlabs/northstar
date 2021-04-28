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
    super::{config::Config, error::Error},
    clone::clone,
    utils::PathExt,
    Container, Intercom, IslandProcess, LaunchProtocol, ENV_NAME, ENV_VERSION, SIGNAL_OFFSET,
};
use crate::runtime::pipe::{Condition, PipeSendRecv};
use anyhow::Context;
use nix::{
    errno::Errno,
    libc::{self, c_int, c_ulong, siginfo_t},
    mount::{self, MsFlags},
    sched,
    sys::{
        self,
        signal::{
            kill, sigaction, signal, SaFlags, SigAction, SigHandler, SigSet, Signal, SIGCHLD,
            SIGKILL,
        },
    },
    unistd::{self, Uid},
};
use npk::manifest::{Dev, Mount, MountFlag};
use sched::CloneFlags;
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    env,
    ffi::{c_void, CString},
    os::unix::io::AsRawFd,
    path::Path,
    process::exit,
};
use sys::wait::{waitpid, WaitStatus};

static mut CHILD_PID: i32 = -1;

#[allow(unused)]
macro_rules! ctrace { ($($arg:tt)+) => (log::trace!("{}: {}", std::process::id(), format!($($arg)+))) }
#[allow(unused)]
macro_rules! cdebug { ($($arg:tt)+) => (log::debug!("{}: {}", std::process::id(), format!($($arg)+))) }
#[allow(unused)]
macro_rules! cinfo { ($($arg:tt)+) => ( log::warn!("{}: {}", std::process::id(), format!($($arg)+))) }
#[allow(unused)]
macro_rules! cwarn { ($($arg:tt)+) => ( log::warn!("{}: {}", std::process::id(), format!($($arg)+))) }
#[allow(unused)]
macro_rules! cerror { ($($arg:tt)+) => ( log::error!("{}: {}", std::process::id(), format!($($arg)+))) }

// Init function. Pid 1.
pub(super) fn init(
    config: &Config,
    container: &Container<IslandProcess>,
    mut fds: HashMap<i32, i32>,
    mut intercom: Intercom,
) -> ! {
    pr_set_name("init").expect("Failed to set init process name");

    // Add intercom to list of fds to preserve
    fds.insert(intercom.0.as_raw_fd(), intercom.0.as_raw_fd());
    fds.insert(intercom.1.as_raw_fd(), intercom.1.as_raw_fd());

    if let Err(e) = prepare(&config, container, fds) {
        println!("Init error: {:?}", e);
        intercom
            .send(LaunchProtocol::Error(e.to_string()))
            .expect("intercom error");
        panic!("Init error: {}", e);
    }

    let id = format!("init-{}", container.manifest.name);

    // Synchronize parent and child startup since we have to rely on a global mut
    // because unix signal handler suck.
    let cond = Condition::new().expect("Failed to create pipe");

    match clone(CloneFlags::empty(), Some(SIGCHLD as i32)) {
        Ok(result) => match result {
            unistd::ForkResult::Parent { child } => {
                // Update global CHILD_PID
                unsafe {
                    CHILD_PID = child.as_raw();
                }

                //println!("{}: Waiting for go", id);
                intercom.recv::<LaunchProtocol>().expect("intercom error");

                // Signal the child it can go
                cond.notify();

                intercom
                    .send(LaunchProtocol::InitReady)
                    .expect("intercom error");

                drop(intercom);

                // TODO: Anything we can do here to free stuff before waiting forever?

                // If the child dies before we waitpid here it becomes a zombie and is catched

                // Wait for the child to exit
                //println!("{}: waiting for {} to exit", id, child);
                let result = waitpid(Some(child), None).expect("waitpid");
                //println!("{}: waitpid result of {}: {:?}", id, child, result);
                match result {
                    WaitStatus::Exited(_pid, status) => exit(status),
                    WaitStatus::Signaled(_pid, status, _) => {
                        // Encode the signal number in the process exit status. It's not possible to raise a
                        // a signal in this "init" process that is received by our parent
                        let code = SIGNAL_OFFSET + status as i32;
                        //println!("{}: exiting with {} (signaled {})", id, code, status);
                        exit(code);
                    }
                    // TODO: Other waitpid results
                    _ => panic!("abnormal exit of child process"),
                };
            }
            unistd::ForkResult::Child => {
                cond.wait();
                drop(intercom);
                reset_signal_handlers();
                set_parent_death_signal(SIGKILL).expect("Failed to set parent death signal");

                let (init, argv, env) = args(&container.manifest);
                println!("{} init: {:?}", id, init);
                println!("{} argv: {:#?}", id, argv);
                println!("{} env: {:#?}", id, env);

                panic!("{}: {:?}", id, unistd::execve(&init, &argv, &env))
            }
        },
        Err(e) => panic!("Fork error: {}", e),
    }
}

/// Prepare the environment in init
fn prepare(
    config: &Config,
    container: &Container<IslandProcess>,
    fds: HashMap<i32, i32>,
) -> anyhow::Result<()> {
    let manifest = &container.manifest;
    let root = container.root.canonicalize()?;

    // Install signal handlers that forward every signal to our child
    init_signal_handlers();

    // Mount
    rootfs(&config, &container).context("Failed to mount")?;

    // Chroot
    cdebug!("Setting chroot to {}", root.display());
    unistd::chroot(&root).context("Failed to chroot")?;

    // Pwd
    cdebug!("Setting pwd to /");
    env::set_current_dir("/").context("Failed to set cwd to /")?;

    // UID / GID
    setid(manifest.uid, manifest.gid).context("Failed to setuid/gid")?;

    cdebug!("Setting no new privs");
    set_no_new_privs(true)?;

    // Become a subreaper for orphans in this namespace
    cdebug!("Setting child subreaper flag");
    set_child_subreaper(true)?;

    // Set the parent process death signal of the calling process to arg2
    // (either a signal value in the range 1..maxsig, or 0 to clear).
    cdebug!("Setting parent death signal to SIGKILL");
    set_parent_death_signal(SIGKILL)?;

    // Capabilities
    drop_capabilities(manifest.capabilities.as_ref()).context("Failed to drop privs")?;

    close_file_descriptors(fds)?;

    // We cannot use log after here because the fd to logd is closed on Android

    Ok(())
}

// TODO: The container could be malformed and the mountpoint might be
// missing. This is not a fault of the RT so don't expect it.
// TODO: mount flags: nosuid etc....
// TODO: /dev mounts from manifest: full or minimal
fn rootfs(config: &Config, container: &Container<IslandProcess>) -> anyhow::Result<()> {
    let none = Option::<&str>::None;
    let root = container.root.canonicalize()?;
    let uid = container.manifest.uid;
    let gid = container.manifest.gid;

    // /proc
    cdebug!("Mounting /proc");
    let source = "/proc";
    let target = root.join("proc");
    mount::mount(none, &target, Some("proc"), MsFlags::empty(), none)
        .context("Failed to mount /proc")?;
    // Remount /proc ro
    cdebug!("Remount /proc read only");
    let flags = MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
    mount::mount(Some(source), &target, none, flags, none).context("Failed to remount /proc")?;

    fn mount_dev(root: &Path, _type: &Dev) -> anyhow::Result<()> {
        // TODO: Dev mount type
        cdebug!("Mounting /dev");
        let source = "/dev/";
        let target = root.join("dev");
        mount::mount(
            Some(source),
            &target,
            Option::<&str>::None,
            MsFlags::MS_BIND,
            Option::<&str>::None,
        )
        .context("Failed to mount /dev")
    }

    // TODO
    if !container
        .manifest
        .mounts
        .iter()
        .any(|(_, mount)| matches!(mount, Mount::Dev { .. }))
    {
        mount_dev(&root, &Dev::Full)?;
    }

    container
        .manifest
        .mounts
        .iter()
        .try_for_each(|(target, mount)| {
            match &mount {
                Mount::Bind { host, flags } => {
                    if !&host.exists() {
                        cdebug!(
                            "Skipping bind mount of nonexitent source {} to {}",
                            host.display(),
                            target.display()
                        );
                        return Ok(());
                    }
                    let rw = flags.contains(&MountFlag::Rw);
                    cdebug!(
                        "Mounting {} on {}{}",
                        host.display(),
                        target.display(),
                        if rw { " (rw)" } else { "" }
                    );
                    let target = root.join_strip(target);
                    mount::mount(Some(host), &target, none, MsFlags::MS_BIND, none)
                        .with_context(|| format!("Failed to bind mount {}", target.display()))?;

                    if !rw {
                        let flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
                        mount::mount(Some(host), &target, none, flags, none)
                            .with_context(|| format!("Failed to remount {}", target.display()))?;
                    }
                }
                Mount::Persist => {
                    let dir = config.data_dir.join(&container.manifest.name);
                    if !dir.exists() {
                        cdebug!("Creating {}", dir.display());
                        std::fs::create_dir_all(&dir).map_err(|e| {
                            Error::Io(format!("Failed to create {}", dir.display()), e)
                        })?;
                    }

                    cdebug!("Chowning {} to {}:{}", dir.display(), uid, gid);
                    unistd::chown(
                        dir.as_os_str(),
                        Some(unistd::Uid::from_raw(uid)),
                        Some(unistd::Gid::from_raw(gid)),
                    )
                    .map_err(|e| {
                        Error::os(
                            format!("Failed to chown {} to {}:{}", dir.display(), uid, gid),
                            e,
                        )
                    })?;

                    cdebug!("Mounting {} on {}", dir.display(), target.display(),);

                    let target = root.join_strip(target);
                    mount::mount(Some(&dir), &target, none, MsFlags::MS_BIND, none)
                        .with_context(|| format!("Failed to bind mount {}", target.display()))?;
                }
                Mount::Resource { name, version, dir } => {
                    let src = {
                        // Join the source of the resource container with the mount dir
                        let resource_root = config.run_dir.join(format!("{}:{}", name, version));
                        let dir = dir
                            .strip_prefix("/")
                            .map(|d| resource_root.join(d))
                            .unwrap_or(resource_root);

                        if !dir.exists() {
                            return Err(anyhow::anyhow!("Missing resource {}", dir.display()));
                        }

                        dir
                    };

                    cdebug!("Mounting {} on {}", src.display(), target.display());

                    let target = root.join_strip(target);
                    mount::mount(Some(&src), &target, none, MsFlags::MS_BIND, none)
                        .with_context(|| format!("Failed to mount {}", target.display()))?;

                    // Remount ro
                    let flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
                    mount::mount(Some(&src), &target, none, flags, none)
                        .with_context(|| format!("Failed to remount {}", target.display()))?;
                }
                Mount::Tmpfs { size } => {
                    cdebug!(
                        "Mounting tmpfs with size {} on {}",
                        bytesize::ByteSize::b(*size),
                        target.display()
                    );
                    let target = root.join_strip(target);
                    let data = format!("size={},mode=1777", size);
                    let flags = MsFlags::empty();
                    mount::mount(none, &target, Some("tmpfs"), flags, Some(data.as_str()))
                        .with_context(|| format!("Failed to bind mount {}", target.display()))?;
                }
                Mount::Dev { r#type } => mount_dev(&root, r#type)?,
            }
            Ok(())
        })?;

    Ok(())
}

// TODO: Do not close the namespace fds?
fn close_file_descriptors(map: HashMap<i32, i32>) -> anyhow::Result<()> {
    let keep: HashSet<i32> = map.keys().cloned().collect();

    for (k, v) in map.iter().filter(|(k, v)| k != v) {
        // If the fd is mappped to a different fd create a copy
        cdebug!("Using fd {} mapped as fd {}", v, k);
        unistd::dup2(*v, *k).context("Failed to dup2")?;
    }

    // Close open fds which are not mapped
    let fds = std::fs::read_dir("/proc/self/fd")
        .context("Readdir of /proc/self/fd")?
        .map(|e| e.unwrap().path())
        .map(|e| e.file_name().unwrap().to_str().unwrap().parse().unwrap())
        .filter(|fd| !keep.contains(fd))
        .collect::<Vec<_>>();

    cdebug!("Closing file descriptors");
    for fd in fds.iter() {
        unistd::close(*fd).ok();
    }

    Ok(())
}

fn args(manifest: &npk::manifest::Manifest) -> (CString, Vec<CString>, Vec<CString>) {
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
                SigSet::empty(),
            );
            sigaction(sig, &action).expect("failed to install sigaction");
        }
    }
}

extern "C" fn forward_signal_to_child(signal: c_int, _: *mut siginfo_t, _: *mut c_void) {
    let child_pid = unsafe { CHILD_PID };
    if child_pid >= 0 {
        let child = nix::unistd::Pid::from_raw(child_pid);
        let signal = Signal::try_from(signal).unwrap();
        // Writing to stdout in signal handler is bad. Just left this here
        // for debugging.
        // println!("{}: forwarding {} to {}", getpid(), signal, child);
        kill(child, Some(signal)).expect("failed to kill child");
    } else {
        // The signal happened before forking the child process or the forking
        // of the child raised this signal. Safe to ignore.
    }
}

fn set_child_subreaper(value: bool) -> anyhow::Result<()> {
    #[cfg(target_os = "android")]
    const PR_SET_CHILD_SUBREAPER: c_int = 36;
    #[cfg(not(target_os = "android"))]
    use libc::PR_SET_CHILD_SUBREAPER;

    let value = if value { 1u64 } else { 0u64 };

    let result = unsafe { nix::libc::prctl(PR_SET_CHILD_SUBREAPER, value, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .context("Failed to set PR_SET_PDEATHSIG")
}

fn set_parent_death_signal(signal: Signal) -> anyhow::Result<()> {
    #[cfg(target_os = "android")]
    const PR_SET_PDEATHSIG: c_int = 1;
    #[cfg(not(target_os = "android"))]
    use libc::PR_SET_PDEATHSIG;

    let result = unsafe { nix::libc::prctl(PR_SET_PDEATHSIG, signal, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .context("Failed to set PR_SET_PDEATHSIG")
}

fn set_no_new_privs(value: bool) -> anyhow::Result<()> {
    #[cfg(target_os = "android")]
    pub const PR_SET_NO_NEW_PRIVS: c_int = 38;
    #[cfg(not(target_os = "android"))]
    use libc::PR_SET_NO_NEW_PRIVS;

    let result = unsafe { nix::libc::prctl(PR_SET_NO_NEW_PRIVS, value as c_ulong, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .context("Failed to set PR_SET_NO_NEW_PRIVS")
}

#[cfg(target_os = "android")]
pub const PR_SET_NAME: c_int = 15;
#[cfg(not(target_os = "android"))]
use libc::PR_SET_NAME;

fn pr_set_name(name: &str) -> anyhow::Result<()> {
    let cname = CString::new(name).unwrap();
    let result = unsafe { libc::prctl(PR_SET_NAME, cname.as_ptr() as c_ulong, 0, 0, 0) };
    Errno::result(result)
        .map(drop)
        .context("Failed to set PR_SET_KEEPCAPS")
}

fn reset_signal_handlers() {
    Signal::iterator()
        .filter(|s| *s != Signal::SIGCHLD)
        .filter(|s| *s != Signal::SIGKILL)
        .filter(|s| *s != Signal::SIGSTOP)
        .try_for_each(|s| unsafe { signal(s, SigHandler::SigDfl) }.map(drop))
        .expect("failed to signal");
}

// Reset effective caps to the most possible set
fn reset_effective_caps() -> anyhow::Result<()> {
    cdebug!("Resetting effective capabilities");
    caps::set(None, caps::CapSet::Effective, &caps::all())
        .context("Failed to reset effective caps")?;
    Ok(())
}

/// Set uid/gid
fn setid(uid: u32, gid: u32) -> anyhow::Result<()> {
    let rt_priveleged = unistd::geteuid() == Uid::from_raw(0);

    // If running as uid 0 safe our caps across the uid/gid drop
    if rt_priveleged {
        caps::securebits::set_keepcaps(true).context("Failed to set keep caps")?;
    }

    let gid = unistd::Gid::from_raw(gid);
    unistd::setresgid(gid, gid, gid).context("Failed to set resgid")?;

    let uid = unistd::Uid::from_raw(uid);
    unistd::setresuid(uid, uid, uid).context("Failed to set resuid")?;

    if rt_priveleged {
        reset_effective_caps()?;
        caps::securebits::set_keepcaps(false).context("Failed to set keep caps")?;
    }

    Ok(())
}

/// Drop capabilities
fn drop_capabilities(cs: Option<&HashSet<caps::Capability>>) -> anyhow::Result<()> {
    let mut bounded = caps::read(None, caps::CapSet::Bounding)?;
    if let Some(caps) = cs {
        bounded.retain(|c| !caps.contains(c));
    }

    cdebug!("Dropping capabilities");
    for cap in bounded {
        // caps::set cannot be called for for bounded
        caps::drop(None, caps::CapSet::Bounding, cap)?;
    }

    if let Some(caps) = cs {
        cdebug!("Settings capabilities to {:?}", caps);
        caps::set(None, caps::CapSet::Effective, caps)?;
        caps::set(None, caps::CapSet::Permitted, caps)?;
        caps::set(None, caps::CapSet::Inheritable, caps)?;
        caps::set(None, caps::CapSet::Ambient, caps)?;
    }

    Ok(())
}
