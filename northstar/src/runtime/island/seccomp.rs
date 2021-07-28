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
    common::non_null_string::NonNullString,
    npk::manifest::{ArgType, Capability, Profile, SyscallArgValues, SyscallRule},
    runtime::island::seccomp_profiles::default,
};
use bindings::{
    seccomp_data, sock_filter, sock_fprog, BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_MAXINSNS,
    BPF_MEM, BPF_RET, BPF_ST, BPF_W, SECCOMP_RET_ALLOW, SECCOMP_RET_KILL, SECCOMP_RET_LOG,
    SYSCALL_MAP,
};
use log::warn;
use nix::errno::Errno;
use std::{
    collections::{HashMap, HashSet},
    mem,
};
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

/// Jump to next instruction and execute
const EVAL_NEXT: u8 = 0;
/// Skip next instruction
const SKIP_NEXT: u8 = 1;

/// Construct a whitelist syscall filter that is applied post clone.
pub(super) fn seccomp_filter(
    profile: Option<&Profile>,
    rules: Option<&HashMap<NonNullString, SyscallRule>>,
    caps: Option<&HashSet<Capability>>,
) -> AllowList {
    let mut builder = Builder::new();
    if let Some(rules) = rules {
        builder.extend(builder_from_rules(rules));
    }
    if let Some(profile) = profile {
        builder.extend(builder_from_profile(profile, caps));
    }
    // builder.log_only(); // TODO: remove
    builder.build()
}

/// Create an AllowList Builder from a list of syscall names
pub fn builder_from_rules(rules: &HashMap<NonNullString, SyscallRule>) -> Builder {
    let mut builder = Builder::new();
    for (name, rule) in rules {
        let arg_vals;
        match rule {
            SyscallRule::All => {
                arg_vals = None;
            }
            SyscallRule::Args(a) => {
                arg_vals = Some(a);
            }
        }
        if let Err(e) = builder.allow_syscall_name(&name.to_string(), arg_vals.cloned()) {
            // Only issue a warning as a missing syscall on the allow list does not lead to insecure behaviour
            warn!("Failed to allow syscall {}: {}", &name.to_string(), e);
        }
    }
    builder
}

/// Create an AllowList Builder from a pre-defined profile
fn builder_from_profile(profile: &Profile, caps: Option<&HashSet<Capability>>) -> Builder {
    match profile {
        Profile::Default => {
            let mut builder = default::BASE.clone();

            // Allow additional syscalls depending on granted capabilities
            if let Some(caps) = caps {
                let mut cap_sys_admin = false;
                for cap in caps {
                    match cap {
                        Capability::CAP_CHOWN => {}
                        Capability::CAP_DAC_OVERRIDE => {}
                        Capability::CAP_DAC_READ_SEARCH => {
                            builder.extend(default::CAP_DAC_READ_SEARCH.clone());
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
                            builder.extend(default::CAP_SYS_ADMIN.clone());
                        }
                        Capability::CAP_NET_RAW => {}
                        Capability::CAP_IPC_LOCK => {}
                        Capability::CAP_IPC_OWNER => {}
                        Capability::CAP_SYS_MODULE => {
                            builder.extend(default::CAP_SYS_MODULE.clone());
                        }
                        Capability::CAP_SYS_RAWIO => {
                            builder.extend(default::CAP_SYS_RAWIO.clone());
                        }
                        Capability::CAP_SYS_CHROOT => {
                            builder.extend(default::CAP_SYS_CHROOT.clone());
                        }
                        Capability::CAP_SYS_PTRACE => {
                            builder.extend(default::CAP_SYS_PTRACE.clone());
                        }
                        Capability::CAP_SYS_PACCT => {
                            builder.extend(default::CAP_SYS_PACCT.clone());
                        }
                        Capability::CAP_SYS_ADMIN => {}
                        Capability::CAP_SYS_BOOT => {
                            builder.extend(default::CAP_SYS_BOOT.clone());
                        }
                        Capability::CAP_SYS_NICE => {
                            builder.extend(default::CAP_SYS_NICE.clone());
                        }
                        Capability::CAP_SYS_RESOURCE => {}
                        Capability::CAP_SYS_TIME => {
                            builder.extend(default::CAP_SYS_TIME.clone());
                        }
                        Capability::CAP_SYS_TTY_CONFIG => {
                            builder.extend(default::CAP_SYS_TTY_CONFIG.clone());
                        }
                        Capability::CAP_MKNOD => {}
                        Capability::CAP_LEASE => {}
                        Capability::CAP_AUDIT_WRITE => {}
                        Capability::CAP_AUDIT_CONTROL => {}
                        Capability::CAP_SETFCAP => {}
                        Capability::CAP_MAC_OVERRIDE => {}
                        Capability::CAP_MAC_ADMIN => {}
                        Capability::CAP_SYSLOG => {
                            builder.extend(default::CAP_SYSLOG.clone());
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
                    builder.extend(default::NON_CAP_SYS_ADMIN.clone());
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
    pub fn apply(&self) -> Result<(), Error> {
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
            filter: self.list.as_ptr() as *mut bindings::sock_filter,
        };
        let sf_prog_ptr = &sf_prog as *const sock_fprog;
        let result = unsafe { nix::libc::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, sf_prog_ptr) };
        Errno::result(result).map_err(Error::Os).map(drop)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
struct NumericSyscallRule {
    /// Number of syscall
    nr: u32,
    /// Argument specific filter rules
    arg_vals: Option<SyscallArgValues>,
}

#[derive(Clone)]
pub struct Builder {
    allowlist: Vec<NumericSyscallRule>,
    log_only: bool,
}

impl Builder {
    /// Create a new seccomp builder
    pub fn new() -> Self {
        let mut builder = Builder {
            allowlist: Vec::new(),
            log_only: false,
        };

        // Add required syscalls (e.g. for execve)
        for syscall in REQUIRED_SYSCALLS {
            builder.allow_syscall_nr(*syscall as u32, None);
        }
        builder
    }

    /// Add syscall number to allowlist
    pub fn allow_syscall_nr(
        &mut self,
        nr: u32,
        arg_vals: Option<SyscallArgValues>,
    ) -> &mut Builder {
        self.allowlist.push(NumericSyscallRule { nr, arg_vals });
        self
    }

    /// Add syscall name to allowlist
    pub fn allow_syscall_name(
        &mut self,
        name: &str,
        arg_vals: Option<SyscallArgValues>,
    ) -> Result<&mut Builder, Error> {
        match translate_syscall(name) {
            Some(nr) => Ok(self.allow_syscall_nr(nr, arg_vals)),
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
        self.allowlist.sort_unstable_by_key(|rule| rule.nr);
        self.allowlist.dedup();

        // Load architecture into accumulator
        let mut filter = AllowList { list: vec![] };
        load_arch_into_acc(&mut filter);

        // Kill process if architecture does not match
        jump_if_acc_is_equal(&mut filter, AUDIT_ARCH, SKIP_NEXT, EVAL_NEXT);
        filter.list.push(bpf_ret(SECCOMP_RET_KILL));

        // Load syscall number into accumulator for subsequent filtering
        load_syscall_nr_into_acc(&mut filter);

        // Add statements for every allowed syscall
        for rule in &self.allowlist {
            if let Some(arg_rule) = &rule.arg_vals {
                // load syscall argument into accumulator
                load_syscall_arg(&mut filter, arg_rule);
                // Compare syscall argument against allowed values
                jump_if_syscall_arg_matches(&mut filter, &arg_rule.values, SKIP_NEXT, EVAL_NEXT);
                // Kill or log if syscall argument did not match
                add_consequence(&mut filter, self.log_only);
                // Restore accumulator with syscall number for subsequent checks
                load_syscall_nr_into_acc(&mut filter);
            } else {
                // If syscall matches return then return 'allow' directly. If not, skip return instruction and go to next check.
                filter.list.push(bpf_jump(
                    BPF_JMP | BPF_JEQ | BPF_K,
                    rule.nr,
                    EVAL_NEXT,
                    SKIP_NEXT,
                ));
                filter.list.push(bpf_ret(SECCOMP_RET_ALLOW));
            }
        }

        // Fall through consequence if not filter rule matched
        add_consequence(&mut filter, self.log_only);

        filter
    }
}

/// Get syscall number by name
fn translate_syscall(name: &str) -> Option<u32> {
    SYSCALL_MAP.get(name).cloned()
}

fn load_arch_into_acc(filter: &mut AllowList) {
    filter.list.push(bpf_stmt(
        BPF_LD | BPF_W | BPF_ABS,
        memoffset::offset_of!(seccomp_data, arch) as u32,
    ));
}

fn load_syscall_nr_into_acc(filter: &mut AllowList) {
    filter.list.push(bpf_stmt(
        BPF_LD | BPF_W | BPF_ABS,
        memoffset::offset_of!(seccomp_data, nr) as u32,
    ));
}

/// On 32 bit architectures: load into accumulator
/// On 64 bit architectures: store in scratch memory
fn load_syscall_arg(filter: &mut AllowList, arg_rule: &SyscallArgValues) {
    let args_offset: usize = memoffset::offset_of!(seccomp_data, args);
    #[cfg(target_pointer_width = "32")]
    {
        const PTR_SIZE: usize = mem::size_of::<u32>();
        filter.list.push(bpf_stmt(
            BPF_LD | BPF_W | BPF_ABS,
            (args_offset + PTR_SIZE * arg_rule.index) as u32,
        ));
    }
    #[cfg(target_pointer_width = "64")]
    {
        // Load high and low parts into scratch memory separately
        const PTR_SIZE: usize = mem::size_of::<u64>();
        // Load low part of argument from seccomp_data
        // TODO: Use register X instead of manual array indexing:
        // BPF_LDX+BPF_W+BPF_IMM
        //    X <- k
        // BPF_LD+BPF_W+BPF_IND
        //    A <- P[X+k:4]
        filter.list.push(bpf_stmt(
            BPF_LD | BPF_W | BPF_ABS,
            (args_offset + PTR_SIZE * arg_rule.index) as u32,
        ));
        // Store accumulator in scratch memory at index 0
        filter.list.push(bpf_stmt(BPF_ST, 0));
        // Get high part of argument from seccomp_data
        filter.list.push(bpf_stmt(
            BPF_LD | BPF_W | BPF_ABS,
            (args_offset + PTR_SIZE * arg_rule.index + (PTR_SIZE / 2)) as u32,
        ));
        // Store accumulator in scratch memory at index 1
        filter.list.push(bpf_stmt(BPF_ST, 1));
    }
}

fn load_scratch_into_acc_lo(filter: &mut AllowList) {
    filter.list.push(bpf_stmt(BPF_LD | BPF_MEM, 0 as u32));
}

fn load_scratch_into_acc_hi(filter: &mut AllowList) {
    filter.list.push(bpf_stmt(BPF_LD | BPF_MEM, 1 as u32));
}

fn jump_if_syscall_arg_matches(
    filter: &mut AllowList,
    allowed_args: &[ArgType],
    offset_true: u8,
    offset_false: u8,
) {
    assert!(allowed_args.len() <= u8::MAX as usize);

    let mut added_instructions = 0;
    for arg in allowed_args {
        // Overflow check
        assert!(offset_true as usize + allowed_args.len() <= u8::MAX as usize);
        assert!(offset_false as usize + allowed_args.len() <= u8::MAX as usize);
        // Underflow check
        assert!(offset_true + allowed_args.len() as u8 >= added_instructions + 1);
        assert!(offset_false + allowed_args.len() as u8 >= added_instructions + 1);
        // Adjust offsets depending on the number of allowed arguments
        let offset_true = offset_true + allowed_args.len() as u8 - (added_instructions + 1);
        let offset_false = offset_false + allowed_args.len() as u8 - (added_instructions + 1);

        #[cfg(target_pointer_width = "32")]
        jump_if_acc_is_equal(filter, *arg, offset_true, offset_false);
        #[cfg(target_pointer_width = "64")]
        jump_if_scratch_is_equal(filter, *arg, offset_true, offset_false);

        added_instructions += 1;
    }
}

/// Compare accumulator (1 instance of a 32 bit register)
fn jump_if_acc_is_equal(filter: &mut AllowList, value: u32, offset_true: u8, offset_false: u8) {
    filter.list.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        value,
        offset_true,
        offset_false,
    ));
}

/// Compare first two 32 bit registers of scratch memory
fn jump_if_scratch_is_equal(filter: &mut AllowList, value: u64, offset_true: u8, offset_false: u8) {
    let high: u32 = (value >> 32) as u32;
    let low: u32 = value as u32;

    // Compare high and low parts of scratch memory separately
    load_scratch_into_acc_lo(filter);
    jump_if_acc_is_equal(filter, low, EVAL_NEXT, offset_false + 2);
    load_scratch_into_acc_hi(filter);
    jump_if_acc_is_equal(filter, high, offset_true, offset_false);
}

fn add_consequence(filter: &mut AllowList, log_only: bool) {
    if log_only {
        filter.list.push(bpf_ret(SECCOMP_RET_LOG));
    } else {
        filter.list.push(bpf_ret(SECCOMP_RET_KILL));
    }
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
