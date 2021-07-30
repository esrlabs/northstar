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
    sock_filter, sock_fprog, BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_MAXINSNS, BPF_MEM,
    BPF_RET, BPF_ST, BPF_W, SECCOMP_RET_ALLOW, SECCOMP_RET_KILL, SECCOMP_RET_LOG, SYSCALL_MAP,
};
use log::warn;
use nix::errno::Errno;
use std::{
    collections::{HashMap, HashSet},
    mem::size_of,
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

// From seccomp man page:
// struct seccomp_data {
//     int   nr;                   /* System call number */
//     __u32 arch;                 /* AUDIT_ARCH_* value
//                                    (see <linux/audit.h>) */
//     __u64 instruction_pointer;  /* CPU instruction pointer */
//     __u64 args[6];              /* Up to 6 system call arguments */
// };
/// Offset of 'nr' member in 'seccomp_data' struct
const SECCOMP_DATA_NR_OFFSET: usize = 0;
/// Size of 'nr' member in 'seccomp_data' struct
const SECCOMP_DATA_NR_SIZE: usize = size_of::<::std::os::raw::c_int>();
/// Offset of 'arch' member in 'seccomp_data' struct
const SECCOMP_DATA_ARCH_OFFSET: usize = SECCOMP_DATA_NR_OFFSET + SECCOMP_DATA_NR_SIZE;
/// Size of 'arch' member in 'seccomp_data' struct
const SECCOMP_DATA_ARCH_SIZE: usize = size_of::<u32>();
/// Offset of 'instruction_pointer' member in 'seccomp_data' struct
const SECCOMP_DATA_INST_P_OFFSET: usize = SECCOMP_DATA_ARCH_OFFSET + SECCOMP_DATA_ARCH_SIZE;
/// Offset of 'instruction_pointer' member in 'seccomp_data' struct
const SECCOMP_DATA_INST_P_SIZE: usize = size_of::<u64>();
/// Offset of 'args' member in 'seccomp_data' struct
const SECCOMP_DATA_ARGS_OFFSET: usize = SECCOMP_DATA_INST_P_OFFSET + SECCOMP_DATA_INST_P_SIZE;
/// Size of elements of 'args' array
const SECCOMP_DATA_ARGS_SIZE: usize = size_of::<u64>();

/// Index to scratch memory where to store/load the high part of an u64 to/from
#[cfg(target_endian = "big")]
const ARG_HIGH_INDEX: u32 = 0;
#[cfg(target_endian = "little")]
const ARG_HIGH_INDEX: u32 = 1;

/// Index to scratch memory where to store/load the low part of an u64 to/from
#[cfg(target_endian = "big")]
const ARG_LOW_INDEX: u32 = 1;
#[cfg(target_endian = "little")]
const ARG_LOW_INDEX: u32 = 0;

/// Construct a whitelist syscall filter that is applied post clone.
pub(super) fn seccomp_filter(
    profile: Option<&Profile>,
    rules: Option<&HashMap<NonNullString, SyscallRule>>,
    caps: Option<&HashSet<Capability>>,
) -> AllowList {
    let mut builder = Builder::new();
    if let Some(profile) = profile {
        builder.extend(builder_from_profile(profile, caps));
    }
    if let Some(rules) = rules {
        builder.extend(builder_from_rules(rules));
    }
    builder.log_only(); // TODO: remove
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
        if let Some(arg_vals) = &arg_vals {
            println!(
                "Allowing syscall {} (arg_vals.index={}, arg_vals.values.len()={})",
                nr,
                arg_vals.index,
                arg_vals.values.len()
            );
        } else {
            println!("Allowing syscall {}", nr);
        }
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

    /// Create seccomp filter ready to apply
    pub fn build(mut self) -> AllowList {
        // sort and dedup syscall numbers to check common syscalls first
        self.allowlist.sort_unstable_by_key(|rule| rule.nr);
        self.allowlist.dedup();

        let mut filter = AllowList { list: vec![] };

        // Load architecture into accumulator
        load_arch_into_acc(&mut filter);

        // Kill process if architecture does not match
        jump_if_acc_is_equal(&mut filter, AUDIT_ARCH, SKIP_NEXT, EVAL_NEXT);
        filter.list.push(bpf_ret(SECCOMP_RET_KILL)); // never just log if architecture does not match

        // Load syscall number into accumulator for subsequent filtering
        load_syscall_nr_into_acc(&mut filter);

        // Add filter block for every allowed syscall
        for rule in &self.allowlist {
            if let Some(arg_rule) = &rule.arg_vals {
                println!("--- Adding conditional syscall rule (rule.nr={})", rule.nr);

                // Precalculate how many instructions to skip if syscall number does not match
                assert!(arg_rule.values.len() <= 50);
                #[cfg(target_pointer_width = "32")]
                let skip_if_false: u8 = 1 + 1 * arg_rule.values.len() + 1;
                #[cfg(target_pointer_width = "64")]
                let skip_if_no_match: u8 = (4 + 4 * arg_rule.values.len() + 1) as u8;

                // If syscall matches continue to check its arguments
                jump_if_acc_is_equal(&mut filter, rule.nr, EVAL_NEXT, skip_if_no_match);
                // load syscall argument into accumulator (32 bit) or scratch memory (64 bit)
                let mut check = 0; // helper instruction counter to verify precalculated value
                check += load_syscall_arg(&mut filter, arg_rule);
                // Compare syscall argument against allowed values
                check += jump_if_arg_matches(&mut filter, &arg_rule.values, EVAL_NEXT, SKIP_NEXT);
                // If syscall argument matches return 'allow' directly
                check += add_success_consequence(&mut filter);
                // Restore accumulator with syscall number for possible next iteration
                assert_eq!(skip_if_no_match as u32, check);
                load_syscall_nr_into_acc(&mut filter);
                println!(
                    "--- Done adding conditional syscall rule (rule.nr={})",
                    rule.nr
                );
            } else {
                // If syscall matches return 'allow' directly
                jump_if_acc_is_equal(&mut filter, rule.nr, EVAL_NEXT, SKIP_NEXT);
                add_success_consequence(&mut filter);
                // No need to restore accumulator with syscall number as we did not overwrite it
            }
        }

        // Fall through consequence if not filter rule matched
        add_fail_consequence(&mut filter, self.log_only);

        filter
    }
}

/// Get syscall number by name
fn translate_syscall(name: &str) -> Option<u32> {
    SYSCALL_MAP.get(name).cloned()
}

fn load_arch_into_acc(filter: &mut AllowList) -> u32 {
    println!("load_arch_into_acc");
    filter.list.push(bpf_stmt(
        BPF_LD | BPF_W | BPF_ABS,
        SECCOMP_DATA_ARCH_OFFSET as u32,
    ));
    return 1;
}

fn load_syscall_nr_into_acc(filter: &mut AllowList) -> u32 {
    println!("load_syscall_nr_into_acc");
    filter.list.push(bpf_stmt(
        BPF_LD | BPF_W | BPF_ABS,
        SECCOMP_DATA_NR_OFFSET as u32,
    ));
    return 1;
}

/// On 32 bit architectures: load into accumulator
/// On 64 bit architectures: store in scratch memory
fn load_syscall_arg(filter: &mut AllowList, arg_rule: &SyscallArgValues) -> u32 {
    println!("load_syscall_arg (arg_rule.index={})", arg_rule.index);
    let mut insts = 0;

    #[cfg(target_pointer_width = "32")]
    {
        insts += load_arg_into_acc(filter, arg_rule);
    }
    #[cfg(target_pointer_width = "64")]
    {
        // Load high and low parts into scratch memory separately
        insts += load_arg_low_into_acc(filter, arg_rule);
        insts += store_acc_in_scratch_low(filter);
        insts += load_arg_high_into_acc(filter, arg_rule);
        insts += store_acc_in_scratch_high(filter);
    }
    insts
}

#[cfg(target_pointer_width = "32")]
fn load_arg_into_acc(filter: &mut AllowList, arg_rule: &SyscallArgValues) -> u32 {
    println!("load_arg_into_acc");
    filter.list.push(bpf_stmt(
        BPF_LD | BPF_W | BPF_ABS,
        (SECCOMP_DATA_ARGS_OFFSET + SECCOMP_DATA_ARGS_SIZE * arg_rule.index) as u32,
    ));
    return 1;
}

#[cfg(target_pointer_width = "64")]
fn load_arg_low_into_acc(filter: &mut AllowList, arg_rule: &SyscallArgValues) -> u32 {
    println!("load_arg_low_into_acc");
    filter.list.push(bpf_stmt(
        BPF_LD | BPF_W | BPF_ABS,
        SECCOMP_DATA_ARGS_OFFSET as u32
            + (SECCOMP_DATA_ARGS_SIZE * arg_rule.index) as u32
            + (ARG_LOW_INDEX * (SECCOMP_DATA_ARGS_SIZE / 2) as u32),
    ));
    return 1;
}

#[cfg(target_pointer_width = "64")]
fn load_arg_high_into_acc(filter: &mut AllowList, arg_rule: &SyscallArgValues) -> u32 {
    println!("load_arg_high_into_acc");
    filter.list.push(bpf_stmt(
        BPF_LD | BPF_W | BPF_ABS,
        SECCOMP_DATA_ARGS_OFFSET as u32
            + (SECCOMP_DATA_ARGS_SIZE * arg_rule.index) as u32
            + (ARG_HIGH_INDEX * (SECCOMP_DATA_ARGS_SIZE / 2) as u32),
    ));
    return 1;
}

fn load_scratch_low_into_acc(filter: &mut AllowList) -> u32 {
    println!("load_scratch_low_into_acc");
    filter
        .list
        .push(bpf_stmt(BPF_LD | BPF_MEM, ARG_LOW_INDEX as u32));
    return 1;
}

fn load_scratch_high_into_acc(filter: &mut AllowList) -> u32 {
    println!("load_scratch_high_into_acc");
    filter
        .list
        .push(bpf_stmt(BPF_LD | BPF_MEM, ARG_HIGH_INDEX as u32));
    return 1;
}

fn store_acc_in_scratch_low(filter: &mut AllowList) -> u32 {
    println!("store_acc_in_scratch_low");
    filter.list.push(bpf_stmt(BPF_ST, ARG_LOW_INDEX));
    return 1;
}

fn store_acc_in_scratch_high(filter: &mut AllowList) -> u32 {
    println!("store_acc_in_scratch_high");
    filter.list.push(bpf_stmt(BPF_ST, ARG_HIGH_INDEX));
    return 1;
}

fn jump_if_arg_matches(
    filter: &mut AllowList,
    arg_vals: &[ArgType],
    jump_true: u8,
    jump_false: u8,
) -> u32 {
    println!(
        "jump_if_syscall_arg_matches (arg_vals.len()={}, jump_true={}, jump_false={})",
        arg_vals.len(),
        jump_true,
        jump_false
    );
    assert!(arg_vals.len() <= u8::MAX as usize);
    let mut insts = 0;

    for (iteration, arg) in arg_vals.iter().enumerate() {
        #[cfg(target_pointer_width = "32")]
        const INSTS_PER_ITER: usize = 1;
        #[cfg(target_pointer_width = "64")]
        const INSTS_PER_ITER: u8 = 4;

        // Overflow check
        assert!(arg_vals.len() > iteration);
        assert!(INSTS_PER_ITER
            .checked_mul((arg_vals.len() - iteration - 1) as u8)
            .is_some());

        // Adjust offsets depending on the number of allowed arguments
        let jump_true = jump_true + INSTS_PER_ITER * (arg_vals.len() - iteration - 1) as u8;
        let jump_false = jump_false + INSTS_PER_ITER * (arg_vals.len() - iteration - 1) as u8;
        println!(
            "Adjusted jumps: jump_true={}, jump_false={}",
            jump_true, jump_false
        );

        #[cfg(target_pointer_width = "32")]
        {
            let old_insts = insts;
            insts += jump_if_acc_is_equal(filter, *arg, jump_true, jump_false);
            assert_eq!(old_insts + INSTS_PER_ITER, insts);
        }
        #[cfg(target_pointer_width = "64")]
        {
            let old_insts = insts;
            insts += jump_if_scratch_is_equal(filter, *arg, jump_true, jump_false);
            assert_eq!(old_insts + INSTS_PER_ITER as u32, insts);
        }
    }
    insts
}

/// Compare accumulator (1 instance of a 32 bit register)
fn jump_if_acc_is_equal(filter: &mut AllowList, value: u32, jump_true: u8, jump_false: u8) -> u32 {
    println!(
        "jump_if_acc_is_equal (value={}, jump_true={}, jump_false={})",
        value, jump_true, jump_false
    );
    filter.list.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        value,
        jump_true,
        jump_false,
    ));
    return 1;
}

#[cfg(target_pointer_width = "64")]
/// Compare first two 32 bit registers of scratch memory
fn jump_if_scratch_is_equal(
    filter: &mut AllowList,
    value: u64,
    jump_true: u8,
    jump_false: u8,
) -> u32 {
    println!(
        "jump_if_scratch_is_equal (value={}, jump_true={}, jump_false={}",
        value, jump_true, jump_false
    );

    let high: u32 = (value >> 32) as u32;
    let low: u32 = value as u32;

    // Compare high and low parts of scratch memory separately
    const INSTS_PER_CHECK: u8 = 2;
    let mut insts = 0;
    insts += load_scratch_low_into_acc(filter);
    insts += jump_if_acc_is_equal(filter, low, EVAL_NEXT, jump_false + INSTS_PER_CHECK);
    let old_insts = insts;
    insts += load_scratch_high_into_acc(filter);
    insts += jump_if_acc_is_equal(filter, high, jump_true, jump_false);
    assert_eq!(old_insts + INSTS_PER_CHECK as u32, insts);
    insts
}

fn add_fail_consequence(filter: &mut AllowList, log_only: bool) -> u32 {
    println!("add_fail_consequence (log_only={})", log_only);
    if log_only {
        filter.list.push(bpf_ret(SECCOMP_RET_LOG));
    } else {
        filter.list.push(bpf_ret(SECCOMP_RET_KILL));
    }
    return 1;
}

fn add_success_consequence(filter: &mut AllowList) -> u32 {
    println!("add_success_consequence");
    filter.list.push(bpf_ret(SECCOMP_RET_ALLOW));
    return 1;
}

// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/filter.h
fn bpf_stmt(code: u32, k: u32) -> sock_filter {
    println!("*bpf_stmt (code={}, k={})", code, k);
    sock_filter {
        code: code as u16,
        k,
        jt: 0,
        jf: 0,
    }
}

fn bpf_jump(code: u32, k: u32, jt: u8, jf: u8) -> sock_filter {
    println!("*bpf_jump (code={}, k={}, jt={}, jf={})", code, k, jt, jf);
    sock_filter {
        code: code as u16,
        k,
        jt,
        jf,
    }
}

fn bpf_ret(k: u32) -> sock_filter {
    println!("bpf_ret (k={})", k);
    bpf_stmt(BPF_RET | BPF_K, k)
}
