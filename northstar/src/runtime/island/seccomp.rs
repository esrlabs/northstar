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

use crate::{
    npk::manifest::Profile,
    runtime::island::seccomp_profile_default::{
        SYSCALLS_DEFAULT, SYSCALLS_DEFAULT_CAP_DAC_READ_SEARCH, SYSCALLS_DEFAULT_CAP_SYSLOG,
        SYSCALLS_DEFAULT_CAP_SYS_ADMIN, SYSCALLS_DEFAULT_CAP_SYS_BOOT,
        SYSCALLS_DEFAULT_CAP_SYS_CHROOT, SYSCALLS_DEFAULT_CAP_SYS_MODULE,
        SYSCALLS_DEFAULT_CAP_SYS_NICE, SYSCALLS_DEFAULT_CAP_SYS_PACCT,
        SYSCALLS_DEFAULT_CAP_SYS_PTRACE, SYSCALLS_DEFAULT_CAP_SYS_RAWIO,
        SYSCALLS_DEFAULT_CAP_SYS_TIME, SYSCALLS_DEFAULT_CAP_SYS_TTY_CONFIG,
        SYSCALLS_DEFAULT_NON_CAP_SYS_ADMIN,
    },
};
use bindings::{
    seccomp_data, sock_filter, sock_fprog, BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_MAXINSNS,
    BPF_RET, BPF_W, SECCOMP_RET_ALLOW, SECCOMP_RET_KILL, SECCOMP_RET_LOG, SYSCALL_MAP,
};
use caps::Capability;
use log::warn;
use nix::errno::Errno;
use std::collections::HashSet;
use thiserror::Error;

#[allow(unused, non_snake_case, non_camel_case_types, non_upper_case_globals)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/syscall_bindings.rs"));
    include!(concat!(env!("OUT_DIR"), "/seccomp_bindings.rs"));

    /// SECCOMP_RET_LOG is implemented by Linux 4.14 but not present in all C libs
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"))]
    pub const SECCOMP_RET_LOG: u32 = 2147221504;
}

#[cfg(all(target_arch = "aarch64"))]
const AUDIT_ARCH: u32 = bindings::AUDIT_ARCH_AARCH64;

#[cfg(all(target_arch = "x86_64"))]
const AUDIT_ARCH: u32 = bindings::AUDIT_ARCH_X86_64;

/// Syscalls used by northstar after the seccomp rules are applied and before the actual execve is done.
const REQUIRED_SYSCALLS: &[u32] = &[bindings::SYS_execve];

// Filter lists that mimic docker's default list
// (https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)
lazy_static::lazy_static! {
    pub static ref BUILDER_DEFAULT: Builder = {
        builder_from_names(&SYSCALLS_DEFAULT.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
    };
}

lazy_static::lazy_static! {
    pub static ref BUILDER_DEFAULT_CAP_DAC_READ_SEARCH: Builder = {
        builder_from_names(&SYSCALLS_DEFAULT_CAP_DAC_READ_SEARCH.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
    };
}

lazy_static::lazy_static! {
    pub static ref BUILDER_DEFAULT_CAP_SYS_ADMIN: Builder = {
        builder_from_names(&SYSCALLS_DEFAULT_CAP_SYS_ADMIN.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
    };
}

lazy_static::lazy_static! {
    pub static ref BUILDER_DEFAULT_CAP_SYS_BOOT: Builder = {
        builder_from_names(&SYSCALLS_DEFAULT_CAP_SYS_BOOT.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
    };
}

lazy_static::lazy_static! {
    pub static ref BUILDER_DEFAULT_CAP_SYS_CHROOT: Builder = {
        builder_from_names(&SYSCALLS_DEFAULT_CAP_SYS_CHROOT.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
    };
}

lazy_static::lazy_static! {
    pub static ref BUILDER_DEFAULT_CAP_SYS_MODULE: Builder = {
        builder_from_names(&SYSCALLS_DEFAULT_CAP_SYS_MODULE.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
    };
}

lazy_static::lazy_static! {
    pub static ref BUILDER_DEFAULT_CAP_SYS_PACCT: Builder = {
        builder_from_names(&SYSCALLS_DEFAULT_CAP_SYS_PACCT.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
    };
}

lazy_static::lazy_static! {
    pub static ref BUILDER_DEFAULT_CAP_SYS_PTRACE: Builder = {
        builder_from_names(&SYSCALLS_DEFAULT_CAP_SYS_PTRACE.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
    };
}

lazy_static::lazy_static! {
    pub static ref BUILDER_DEFAULT_CAP_SYS_RAWIO: Builder = {
        builder_from_names(&SYSCALLS_DEFAULT_CAP_SYS_RAWIO.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
    };
}

lazy_static::lazy_static! {
    pub static ref BUILDER_DEFAULT_CAP_SYS_TIME: Builder = {
        builder_from_names(&SYSCALLS_DEFAULT_CAP_SYS_TIME.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
    };
}

lazy_static::lazy_static! {
    pub static ref BUILDER_DEFAULT_CAP_SYS_TTY_CONFIG: Builder = {
        builder_from_names(&SYSCALLS_DEFAULT_CAP_SYS_TTY_CONFIG.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
    };
}

lazy_static::lazy_static! {
    pub static ref BUILDER_DEFAULT_CAP_SYS_NICE: Builder = {
        builder_from_names(&SYSCALLS_DEFAULT_CAP_SYS_NICE.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
    };
}

lazy_static::lazy_static! {
    pub static ref BUILDER_DEFAULT_CAP_SYSLOG: Builder = {
        builder_from_names(&SYSCALLS_DEFAULT_CAP_SYSLOG.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
    };
}

lazy_static::lazy_static! {
    pub static ref BUILDER_DEFAULT_NON_CAP_SYS_ADMIN: Builder = {
        builder_from_names(&SYSCALLS_DEFAULT_NON_CAP_SYS_ADMIN.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
    };
}

/// Construct a whitelist syscall filter that is applied post clone.
pub(super) fn seccomp_filter(
    profile: Option<&Profile>,
    names: Option<&HashSet<String>>,
    caps: Option<&HashSet<Capability>>,
) -> AllowList {
    let mut builder = Builder::new();
    if let Some(names) = names {
        builder.extend(builder_from_names(&names));
    }
    if let Some(profile) = profile {
        builder.extend(builder_from_profile(&profile, caps));
    }
    builder.build()
}

/// Create an AllowList Builder from a list of syscall names
fn builder_from_names(names: &HashSet<String>) -> Builder {
    let mut builder = Builder::new();
    for name in names {
        if let Err(e) = builder.allow_syscall_name(&name.to_string()) {
            // Continue here as a missing syscall on the allow list does not lead to insecure behaviour
            warn!("Failed to allow syscall {}: {}", &name.to_string(), e);
        }
    }
    builder
}

/// Create an AllowList Builder from a pre-defined profile
fn builder_from_profile(profile: &Profile, caps: Option<&HashSet<Capability>>) -> Builder {
    match profile {
        Profile::Default => {
            let mut builder = BUILDER_DEFAULT.clone();

            // Allow additional syscalls depending on granted capabilities
            if let Some(caps) = caps {
                let mut cap_sys_admin = false;
                for cap in caps {
                    match cap {
                        Capability::CAP_CHOWN => {}
                        Capability::CAP_DAC_OVERRIDE => {}
                        Capability::CAP_DAC_READ_SEARCH => {
                            builder.extend(BUILDER_DEFAULT_CAP_DAC_READ_SEARCH.clone());
                        }
                        Capability::CAP_FOWNER => {}
                        Capability::CAP_FSETID => {}
                        Capability::CAP_KILL => {}
                        Capability::CAP_SETGID => {}
                        Capability::CAP_SETUID => {}
                        Capability::CAP_SETPCAP => {}
                        Capability::CAP_LINUX_IMMUTABLE => {}
                        Capability::CAP_NET_BIND_SERVICE => {}
                        Capability::CAP_NET_BROADCAST => {}
                        Capability::CAP_NET_ADMIN => {
                            cap_sys_admin = true;
                            builder.extend(BUILDER_DEFAULT_CAP_SYS_ADMIN.clone());
                        }
                        Capability::CAP_NET_RAW => {}
                        Capability::CAP_IPC_LOCK => {}
                        Capability::CAP_IPC_OWNER => {}
                        Capability::CAP_SYS_MODULE => {
                            builder.extend(BUILDER_DEFAULT_CAP_SYS_MODULE.clone());
                        }
                        Capability::CAP_SYS_RAWIO => {
                            builder.extend(BUILDER_DEFAULT_CAP_SYS_RAWIO.clone());
                        }
                        Capability::CAP_SYS_CHROOT => {
                            builder.extend(BUILDER_DEFAULT_CAP_SYS_CHROOT.clone());
                        }
                        Capability::CAP_SYS_PTRACE => {
                            builder.extend(BUILDER_DEFAULT_CAP_SYS_PTRACE.clone());
                        }
                        Capability::CAP_SYS_PACCT => {
                            builder.extend(BUILDER_DEFAULT_CAP_SYS_PACCT.clone());
                        }
                        Capability::CAP_SYS_ADMIN => {}
                        Capability::CAP_SYS_BOOT => {
                            builder.extend(BUILDER_DEFAULT_CAP_SYS_BOOT.clone());
                        }
                        Capability::CAP_SYS_NICE => {
                            builder.extend(BUILDER_DEFAULT_CAP_SYS_NICE.clone());
                        }
                        Capability::CAP_SYS_RESOURCE => {}
                        Capability::CAP_SYS_TIME => {
                            builder.extend(BUILDER_DEFAULT_CAP_SYS_TIME.clone());
                        }
                        Capability::CAP_SYS_TTY_CONFIG => {
                            builder.extend(BUILDER_DEFAULT_CAP_SYS_TTY_CONFIG.clone());
                        }
                        Capability::CAP_MKNOD => {}
                        Capability::CAP_LEASE => {}
                        Capability::CAP_AUDIT_WRITE => {}
                        Capability::CAP_AUDIT_CONTROL => {}
                        Capability::CAP_SETFCAP => {}
                        Capability::CAP_MAC_OVERRIDE => {}
                        Capability::CAP_MAC_ADMIN => {}
                        Capability::CAP_SYSLOG => {
                            builder.extend(BUILDER_DEFAULT_CAP_SYSLOG.clone());
                        }
                        Capability::CAP_WAKE_ALARM => {}
                        Capability::CAP_BLOCK_SUSPEND => {}
                        Capability::CAP_AUDIT_READ => {}
                        Capability::CAP_PERFMON => {}
                        Capability::CAP_BPF => {}
                        Capability::CAP_CHECKPOINT_RESTORE => {}
                        Capability::__Nonexhaustive => {}
                    };
                }
                if !cap_sys_admin {
                    builder.extend(BUILDER_DEFAULT_NON_CAP_SYS_ADMIN.clone());
                }
            }
            builder
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid arguments")]
    InvalidArguments,
    #[error("Unknown system call {0}")]
    UnknownSyscall(String),
    #[error("OS error: {0}")]
    Os(nix::Error),
}

// Read-only list of allowed syscalls. Methods do not cause memory allocations on the heap.
#[derive(Clone, Debug, Default)]
pub struct AllowList {
    list: Vec<sock_filter>,
}

impl AllowList {
    pub fn apply(&mut self) -> Result<(), Error> {
        #[cfg(target_os = "android")]
        const PR_SET_SECCOMP: nix::libc::c_int = 22;

        #[cfg(target_os = "android")]
        const SECCOMP_MODE_FILTER: nix::libc::c_int = 2;

        #[cfg(not(target_os = "android"))]
        use nix::libc::PR_SET_SECCOMP;

        #[cfg(not(target_os = "android"))]
        use nix::libc::SECCOMP_MODE_FILTER;

        if self.list.len() > BPF_MAXINSNS as usize {
            return Err(Error::InvalidArguments);
        }

        let sf_prog = sock_fprog {
            len: self.list.len() as u16,
            filter: self.list.as_mut_ptr(),
        };
        let sf_prog_ptr = &sf_prog as *const sock_fprog;
        let result = unsafe { nix::libc::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, sf_prog_ptr) };
        Errno::result(result).map_err(Error::Os).map(drop)
    }
}

#[derive(Clone)]
pub struct Builder {
    allowlist: Vec<u32>,
    log_only: bool,
}

impl Builder {
    const EVAL_NEXT: u8 = 0;
    const SKIP_NEXT: u8 = 1;

    /// Create a new seccomp builder
    pub fn new() -> Self {
        let mut builder = Builder {
            allowlist: Vec::new(),
            log_only: false,
        };

        // Add required syscalls (e.g. for execve)
        for syscall in REQUIRED_SYSCALLS {
            builder.allow_syscall_nr(*syscall as u32);
        }
        builder
    }

    /// Add syscall number to whitelist
    pub fn allow_syscall_nr(&mut self, nr: u32) -> &mut Builder {
        self.allowlist.push(nr);
        self
    }

    /// Add syscall name to whitelist
    pub fn allow_syscall_name(&mut self, name: &str) -> Result<&mut Builder, Error> {
        match translate_syscall(name) {
            Some(nr) => Ok(self.allow_syscall_nr(nr)),
            None => Err(Error::UnknownSyscall(name.into())),
        }
    }

    /// Log syscall violations only
    #[allow(unused)]
    pub fn log_only(&mut self) -> &mut Builder {
        self.log_only = true;
        self
    }

    /// Extend one builder with another builder
    ///
    /// Note: The 'log_only' property of the extended builder is only set to true if it was true in both original builders
    pub fn extend(&mut self, other: Builder) -> &mut Builder {
        self.allowlist.extend(other.allowlist);
        self.log_only &= other.log_only;
        self
    }

    /// Apply seccomp rules
    pub fn build(mut self) -> AllowList {
        // sort and dedup syscall numbers to check common syscalls first
        self.allowlist.sort_unstable();
        self.allowlist.dedup();

        // Load architecture into accumulator
        let mut list = AllowList { list: vec![] };
        list.list.push(bpf_stmt(
            BPF_LD | BPF_W | BPF_ABS,
            memoffset::offset_of!(seccomp_data, arch) as u32,
        ));

        // Kill process if architecture does not match
        list.list.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            AUDIT_ARCH,
            Builder::SKIP_NEXT,
            Builder::EVAL_NEXT,
        ));
        list.list.push(bpf_ret(SECCOMP_RET_KILL));

        // Load system call number into accumulator for subsequent filtering
        list.list.push(bpf_stmt(
            BPF_LD | BPF_W | BPF_ABS,
            memoffset::offset_of!(seccomp_data, nr) as u32,
        ));

        // Add statements for every allowed syscall
        for nr in &self.allowlist {
            // If syscall matches return 'allow' directly. If not, skip return instruction and go to next check.
            list.list.push(bpf_jump(
                BPF_JMP | BPF_JEQ | BPF_K,
                *nr,
                Builder::EVAL_NEXT,
                Builder::SKIP_NEXT,
            ));
            list.list.push(bpf_ret(SECCOMP_RET_ALLOW));
        }

        // Finish by adding consequence for calling a prohibited syscall
        if self.log_only {
            list.list.push(bpf_ret(SECCOMP_RET_LOG));
        } else {
            list.list.push(bpf_ret(SECCOMP_RET_KILL));
        }

        list
    }
}

/// Get syscall number by name
fn translate_syscall(name: &str) -> Option<u32> {
    SYSCALL_MAP.get(name).cloned()
}

// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/filter.h
fn bpf_stmt(code: u32, k: u32) -> sock_filter {
    sock_filter {
        code: code as u16,
        k,
        jt: 0,
        jf: 0,
    }
}

fn bpf_jump(code: u32, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter {
        code: code as u16,
        k,
        jt,
        jf,
    }
}

fn bpf_ret(k: u32) -> sock_filter {
    bpf_stmt(BPF_RET | BPF_K, k)
}
