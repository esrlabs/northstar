use crate::{
    common::non_nul_string::NonNulString,
    npk::manifest::Capability,
    seccomp::{profiles::default, Profile, SyscallArgRule, SyscallRule},
};
use bindings::{
    seccomp_data, sock_filter, sock_fprog, BPF_ABS, BPF_ALU, BPF_AND, BPF_IMM, BPF_JEQ, BPF_JMP,
    BPF_K, BPF_LD, BPF_MAXINSNS, BPF_MEM, BPF_NEG, BPF_OR, BPF_RET, BPF_ST, BPF_W, SYSCALL_MAP,
};
use log::trace;
use nix::errno::Errno;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::{HashMap, HashSet},
    mem::size_of,
};
use thiserror::Error;

#[allow(unused, non_snake_case, non_camel_case_types, non_upper_case_globals)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/syscall_bindings.rs"));
    include!(concat!(env!("OUT_DIR"), "/seccomp_bindings.rs"));
}

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = bindings::AUDIT_ARCH_AARCH64;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = bindings::AUDIT_ARCH_X86_64;

/// Syscalls used by northstar after the seccomp rules are applied and before the actual execve is done.
const REQUIRED_SYSCALLS: &[u32] = &[bindings::SYS_execve];

/// Jump to next instruction and execute
const EVAL_NEXT: u8 = 0;
/// Skip next instruction
const SKIP_NEXT: u8 = 1;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Seccomp filter list exceeds maximum number of BPF statements")]
    ListTooLong,
    #[error("Unknown system call {0}")]
    UnknownSyscall(String),
    #[error("OS error: {0}")]
    Os(nix::Error),
}

/// Construct a allowlist syscall filter that is applied post clone.
pub fn seccomp_filter(
    profile: Option<&Profile>,
    rules: Option<&HashMap<NonNulString, SyscallRule>>,
    caps: &HashSet<Capability>,
) -> AllowList {
    check_platform_requirements();

    let mut builder = Builder::new();
    if let Some(profile) = profile {
        builder.extend(builder_from_profile(profile, caps));
    }
    if let Some(rules) = rules {
        builder.extend(builder_from_rules(rules));
    }
    builder.build()
}

/// Create an AllowList Builder from a list of syscall names
pub(crate) fn builder_from_rules(rules: &HashMap<NonNulString, SyscallRule>) -> Builder {
    let mut builder = Builder::new();
    for (name, call_rule) in rules {
        let arg_rule = match call_rule {
            SyscallRule::Any => None,
            SyscallRule::Args(a) => Some(a),
        };
        if let Err(e) = builder.allow_syscall_name(name, arg_rule.cloned()) {
            // Only issue a warning as a missing syscall on the allow list does not lead to insecure behaviour
            trace!("failed to allow syscall {}: {}", &name.to_string(), e);
        }
    }
    builder
}

/// Create an AllowList Builder from a pre-defined profile
fn builder_from_profile(profile: &Profile, caps: &HashSet<Capability>) -> Builder {
    match profile {
        Profile::Default => {
            let mut builder = default::BASE.clone();

            // Allow additional syscalls depending on granted capabilities
            if !caps.is_empty() {
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

/// Check if the current platform is supported and return an error if not
fn check_platform_requirements() {
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    compile_error!("seccomp is only supported on aarch64 and x86_64");
    #[cfg(target_pointer_width = "32")]
    compile_error!("seccomp is not supported on 32 Bit architectures");
    #[cfg(target_endian = "big")]
    compile_error!("seccomp is not supported on Big Endian architectures");
}

#[derive(Clone, Debug, PartialEq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl Serialize for SockFilter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let a = (self.code as u32) << 16 | (self.jt as u32) << 8 | self.jf as u32;
        let value = (a as u64) << 32 | self.k as u64;
        serializer.serialize_u64(value)
    }
}

impl<'de> Deserialize<'de> for SockFilter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        let a = (value >> 32) as u32;
        let code = ((a & 0xFFFF0000) >> 16) as u16;
        let jt = ((a & 0xFF00) >> 8) as u8;
        let jf = (a & 0xFF) as u8;
        let k = (value & 0xFFFFFFFF) as u32;
        Ok(SockFilter { code, jt, jf, k })
    }
}

impl From<&SockFilter> for sock_filter {
    fn from(s: &SockFilter) -> sock_filter {
        sock_filter {
            code: s.code,
            jt: s.jt,
            jf: s.jf,
            k: s.k,
        }
    }
}

/// Read-only list of allowed syscalls. Methods do not cause memory allocations on the heap.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AllowList {
    list: Vec<SockFilter>,
}

impl AllowList {
    /// Apply this seccomp filter settings to the current thread
    pub fn apply(&self) -> Result<(), Error> {
        #[cfg(target_os = "android")]
        const PR_SET_SECCOMP: nix::libc::c_int = 22;
        #[cfg(target_os = "android")]
        const SECCOMP_MODE_FILTER: nix::libc::c_int = 2;

        #[cfg(not(target_os = "android"))]
        use nix::libc::{PR_SET_SECCOMP, SECCOMP_MODE_FILTER};

        if self.list.len() > BPF_MAXINSNS as usize {
            return Err(Error::ListTooLong);
        }

        // Convert the list of instructions into the bindings sock_filter
        let list = self
            .list
            .iter()
            .map(Into::into)
            .collect::<Vec<sock_filter>>();

        let sf_prog = sock_fprog {
            len: list.len() as u16,
            filter: list.as_ptr() as *mut bindings::sock_filter,
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
    /// Allowed argument values. If no values are defined, the syscall is allowed unconditionally.
    arg_rule: Option<SyscallArgRule>,
}

/// Builder for AllowList struct
#[derive(Default, Clone)]
pub struct Builder {
    allowlist: Vec<NumericSyscallRule>,
    log_only: bool,
}

impl Builder {
    /// Create a new seccomp builder
    pub fn new() -> Self {
        let mut builder: Builder = Default::default();

        // Add required syscalls (e.g. for execve)
        for syscall in REQUIRED_SYSCALLS {
            builder.allow_syscall_nr(*syscall as u32, None);
        }
        builder
    }

    /// Add syscall to allowlist by number
    pub(crate) fn allow_syscall_nr(
        &mut self,
        nr: u32,
        arg_rule: Option<SyscallArgRule>,
    ) -> &mut Builder {
        self.allowlist.push(NumericSyscallRule { nr, arg_rule });
        self
    }

    /// Add syscall to allowlist by name
    pub(crate) fn allow_syscall_name(
        &mut self,
        name: &str,
        arg_rule: Option<SyscallArgRule>,
    ) -> Result<&mut Builder, Error> {
        match translate_syscall(name) {
            Some(nr) => Ok(self.allow_syscall_nr(nr, arg_rule)),
            None => Err(Error::UnknownSyscall(name.into())),
        }
    }

    /// Log syscall violations instead of aborting the program
    #[allow(unused)]
    pub(crate) fn log_only(&mut self) -> &mut Builder {
        self.log_only = true;
        self
    }

    /// Extend one builder with another builder.
    /// Note: The 'log_only' property of the extended builder is only set to true if it was true in both original builders.
    pub(crate) fn extend(&mut self, other: Builder) -> &mut Builder {
        self.allowlist.extend(other.allowlist);
        self.log_only &= other.log_only;
        self
    }

    /// Create seccomp filter ready to apply
    pub(crate) fn build(mut self) -> AllowList {
        // sort and dedup syscall numbers to check common syscalls first
        self.allowlist.sort_unstable_by_key(|rule| rule.nr);
        self.allowlist.dedup();

        let mut filter = AllowList { list: vec![] };

        // Load architecture into accumulator
        load_arch_into_acc(&mut filter);

        // Kill process if architecture does not match
        jump_if_acc_is_equal(&mut filter, AUDIT_ARCH, SKIP_NEXT, EVAL_NEXT);
        filter.list.push(bpf_ret(nix::libc::SECCOMP_RET_KILL));

        // Load syscall number into accumulator for subsequent filtering
        load_syscall_nr_into_acc(&mut filter);

        // Add filter block for every allowed syscall
        for rule in &self.allowlist {
            if let Some(arg_rule) = &rule.arg_rule {
                if let Some(values) = &arg_rule.values {
                    trace!("Adding seccomp argument block (nr={})", rule.nr);

                    // Precalculate number of instructions to skip if syscall number does not match
                    assert!(values.len() <= ((u8::MAX - 5) / 4) as usize); // Detect u8 overflow
                    let skip_if_no_match: u8 = (4 + 4 * values.len() + 1) as u8;

                    // If syscall matches continue to check its arguments
                    jump_if_acc_is_equal(&mut filter, rule.nr, EVAL_NEXT, skip_if_no_match);
                    // Helper instruction counter to verify precalculated jump value
                    let mut insts = 0;
                    // Load syscall argument into scratch memory
                    insts += load_syscall_arg_into_scratch(&mut filter, arg_rule);
                    // Compare syscall argument against allowed values
                    insts += jump_if_scratch_matches(&mut filter, values, EVAL_NEXT, SKIP_NEXT);
                    // If syscall argument matches return 'allow' directly
                    insts += return_success(&mut filter);
                    assert_eq!(skip_if_no_match as u32, insts);
                    // Restore accumulator with syscall number for possible next iteration
                    load_syscall_nr_into_acc(&mut filter);

                    trace!("Finished seccomp argument block (nr={})", rule.nr);
                }
                if let Some(mask) = arg_rule.mask {
                    trace!(
                        "Adding seccomp argument block (nr={}, mask={})",
                        rule.nr,
                        mask
                    );

                    // Precalculate number of instructions to skip if syscall number does not match
                    let skip_if_no_match: u8 = (4 + 6 + 1) as u8;

                    // If syscall matches continue to check its arguments
                    jump_if_acc_is_equal(&mut filter, rule.nr, EVAL_NEXT, skip_if_no_match);
                    // Helper instruction counter to verify precalculated jump value
                    let mut insts = 0;
                    // Load syscall argument into accumulator (32 bit) or scratch memory (64 bit)
                    insts += load_syscall_arg_into_scratch(&mut filter, arg_rule);
                    // Compare syscall argument against mask
                    insts += jump_if_scratch_matches_mask(&mut filter, mask, EVAL_NEXT, SKIP_NEXT);
                    insts += return_success(&mut filter);
                    // Restore accumulator with syscall number for possible next iteration
                    assert_eq!(skip_if_no_match as u32, insts);
                    load_syscall_nr_into_acc(&mut filter);

                    trace!(
                        "Finished seccomp arg. block (nr={}, mask={})",
                        rule.nr,
                        mask
                    );
                }
            } else {
                trace!("Adding seccomp syscall block (nr={})", rule.nr);

                // If syscall matches return 'allow' directly
                jump_if_acc_is_equal(&mut filter, rule.nr, EVAL_NEXT, SKIP_NEXT);
                return_success(&mut filter);
                // No need to restore accumulator with syscall number as we did not overwrite it

                trace!("Finished seccomp syscall block (nr={})", rule.nr);
            }
        }

        // Fall through consequence if not filter rule matched
        return_fail(&mut filter, self.log_only);

        filter
    }
}

/// Get syscall number by name
fn translate_syscall(name: &str) -> Option<u32> {
    SYSCALL_MAP.get(name).cloned()
}

/// Load architecture identifier number into accumulator
fn load_arch_into_acc(filter: &mut AllowList) -> u32 {
    filter.list.push(bpf_stmt(
        BPF_LD | BPF_W | BPF_ABS,
        memoffset::offset_of!(seccomp_data, arch) as u32,
    ));
    1
}

/// Load the number of the syscall into accumulator
fn load_syscall_nr_into_acc(filter: &mut AllowList) -> u32 {
    filter.list.push(bpf_stmt(
        BPF_LD | BPF_W | BPF_ABS,
        memoffset::offset_of!(seccomp_data, nr) as u32,
    ));
    1
}

/// Load syscall argument into the first two 32-bit registers of scratch memory
fn load_syscall_arg_into_scratch(filter: &mut AllowList, arg_rule: &SyscallArgRule) -> u32 {
    // Load high and low parts into scratch memory separately
    let mut insts = 0;
    insts += load_arg_low_into_acc(filter, arg_rule);
    insts += store_acc_in_scratch_low(filter);
    insts += load_arg_high_into_acc(filter, arg_rule);
    insts += store_acc_in_scratch_high(filter);
    insts
}

/// Load 32 low bits of syscall argument into 32-bit accumulator
fn load_arg_low_into_acc(filter: &mut AllowList, arg_rule: &SyscallArgRule) -> u32 {
    filter.list.push(bpf_stmt(
        BPF_LD | BPF_W | BPF_ABS,
        arg_low_array_offset(arg_rule.index) as u32,
    ));
    1
}

/// Load 32 high bits of syscall argument into 32-bit accumulator
fn load_arg_high_into_acc(filter: &mut AllowList, arg_rule: &SyscallArgRule) -> u32 {
    filter.list.push(bpf_stmt(
        BPF_LD | BPF_W | BPF_ABS,
        arg_high_array_offset(arg_rule.index) as u32,
    ));
    1
}

// From seccomp man page:
// struct seccomp_data {
//     int   nr;                   /* System call number */
//     __u32 arch;                 /* AUDIT_ARCH_* value (see <linux/audit.h>) */
//     __u64 instruction_pointer;  /* CPU instruction pointer */
//     __u64 args[6];              /* Up to 6 system call arguments */
// };
/// Size of elements of 'args' array
const SECCOMP_DATA_ARGS_SIZE: usize = size_of::<u64>();

/// Get the offset of 'args' array entry in the 'seccomp_data' struct that holds the 32 low bits of syscall argument
fn arg_low_array_offset(index: usize) -> usize {
    memoffset::offset_of!(seccomp_data, args) + (index * SECCOMP_DATA_ARGS_SIZE)
}

/// Get the offset of 'args' array entry in the 'seccomp_data' struct that holds the 32 high bits of syscall argument
fn arg_high_array_offset(index: usize) -> usize {
    memoffset::offset_of!(seccomp_data, args)
        + (index * SECCOMP_DATA_ARGS_SIZE)
        + (SECCOMP_DATA_ARGS_SIZE / 2)
}

/// Load given value into accumulator
fn _load_into_acc(filter: &mut AllowList, value: u32) -> u32 {
    filter.list.push(bpf_stmt(BPF_LD | BPF_IMM, value));
    1
}

const SCRATCH_LOW_INDEX: u32 = 0;
const SCRATCH_HIGH_INDEX: u32 = 1;

/// Load the first 32-bit register of scratch memory into register
fn load_scratch_low_into_acc(filter: &mut AllowList) -> u32 {
    filter
        .list
        .push(bpf_stmt(BPF_LD | BPF_MEM, SCRATCH_LOW_INDEX));
    1
}

/// Load the second 32-bit register of scratch memory into register
fn load_scratch_high_into_acc(filter: &mut AllowList) -> u32 {
    filter
        .list
        .push(bpf_stmt(BPF_LD | BPF_MEM, SCRATCH_HIGH_INDEX));
    1
}

/// Store accumulator into the first 32-bit register of scratch memory
fn store_acc_in_scratch_low(filter: &mut AllowList) -> u32 {
    filter.list.push(bpf_stmt(BPF_ST, SCRATCH_LOW_INDEX));
    1
}

/// Store accumulator into the second 32-bit register of scratch memory
fn store_acc_in_scratch_high(filter: &mut AllowList) -> u32 {
    filter.list.push(bpf_stmt(BPF_ST, SCRATCH_HIGH_INDEX));
    1
}

/// Perform jump if the first two 32-bit scratch registers match the given 64-bit value
fn jump_if_scratch_matches(
    filter: &mut AllowList,
    values: &[u64],
    jump_true: u8,
    jump_false: u8,
) -> u32 {
    assert!(values.len() <= u8::MAX as usize);
    let mut insts = 0;

    for (iteration, value) in values.iter().enumerate() {
        const INSTS_PER_ITER: u8 = 4; // 2 * load_scratch + 2 * jump_if_acc_is_equal

        // Overflow check
        assert!(values.len() > iteration);
        let offset_adjust = INSTS_PER_ITER
            .checked_mul((values.len() - iteration - 1) as u8)
            .expect("BCP offset overflow");

        // Adjust offsets depending on the number of allowed arguments
        let jump_true = jump_true + offset_adjust;
        let jump_false = jump_false + offset_adjust;

        // Compare accumulator with scratch memory
        let insts_before = insts;
        insts += jump_if_scratch_is_equal(filter, *value, jump_true, jump_false);
        assert_eq!(insts_before + INSTS_PER_ITER as u32, insts);
    }
    insts
}

/// Compare accumulator (32 bit) against given value
fn jump_if_acc_is_equal(filter: &mut AllowList, value: u32, jump_true: u8, jump_false: u8) -> u32 {
    filter.list.push(bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        value,
        jump_true,
        jump_false,
    ));
    1
}

/// Jump if accumulator has no bits set outside the given mask
fn jump_if_acc_matches_mask(
    filter: &mut AllowList,
    mask: u32,
    jump_true: u8,
    jump_false: u8,
) -> u32 {
    let mut insts = 0;
    filter.list.push(bpf_and(!mask)); // Keep only non-masked ones
    insts += 1;
    insts += jump_if_acc_is_equal(filter, 0, jump_true, jump_false);
    insts
}

/// Compare first two 32 bit registers of scratch memory with value
fn jump_if_scratch_is_equal(
    filter: &mut AllowList,
    value: u64,
    jump_true: u8,
    jump_false: u8,
) -> u32 {
    // Compare high and low parts of scratch memory separately
    let low: u32 = value as u32;
    let high: u32 = (value >> 32) as u32;
    let mut insts = 0;
    insts += load_scratch_low_into_acc(filter);
    insts += jump_if_acc_is_equal(filter, low, EVAL_NEXT, jump_false + 2);
    insts += load_scratch_high_into_acc(filter);
    insts += jump_if_acc_is_equal(filter, high, jump_true, jump_false);
    insts
}

/// Match first two 32 bit registers of scratch memory against bitmask
fn jump_if_scratch_matches_mask(
    filter: &mut AllowList,
    mask: u64,
    jump_true: u8,
    jump_false: u8,
) -> u32 {
    const INSTS_PER_CHECK: u8 = 3;

    // Check high and low parts of scratch memory separately
    let low: u32 = mask as u32;
    let high: u32 = (mask >> 32) as u32;
    let mut insts = 0;
    let insts_before = insts;
    insts += load_scratch_low_into_acc(filter);
    insts += jump_if_acc_matches_mask(filter, low, EVAL_NEXT, jump_false + INSTS_PER_CHECK);
    assert_eq!(insts_before + INSTS_PER_CHECK as u32, insts);
    insts += load_scratch_high_into_acc(filter);
    insts += jump_if_acc_matches_mask(filter, high, jump_true, jump_false);
    assert_eq!(insts_before + 2 * INSTS_PER_CHECK as u32, insts);
    insts
}

/// Add statement that causes the BPF program return and prohibit the syscall
fn return_fail(filter: &mut AllowList, log_only: bool) -> u32 {
    if log_only {
        filter.list.push(bpf_ret(nix::libc::SECCOMP_RET_LOG));
    } else {
        filter.list.push(bpf_ret(nix::libc::SECCOMP_RET_KILL));
    }
    1
}

/// Add statement that causes the BPF program return and allow the syscall
fn return_success(filter: &mut AllowList) -> u32 {
    trace!("add_success");
    filter.list.push(bpf_ret(nix::libc::SECCOMP_RET_ALLOW));
    1
}

/// Negate accumulator
fn _bpf_neg() -> SockFilter {
    trace!("bpf_neg");
    bpf_stmt(BPF_ALU | BPF_NEG, 0)
}

/// And accumulator with value
fn bpf_and(k: u32) -> SockFilter {
    trace!("bpf_and({})", k);
    bpf_stmt(BPF_ALU | BPF_AND | BPF_K, k)
}

/// Or accumulator with value
fn _bpf_or(k: u32) -> SockFilter {
    trace!("bpf_or({})", k);
    bpf_stmt(BPF_ALU | BPF_OR | BPF_K, k)
}

/// Add return clause (e.g. allow, kill, log)
fn bpf_ret(k: u32) -> SockFilter {
    trace!("bpf_ret({})", k);
    bpf_stmt(BPF_RET | BPF_K, k)
}

// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/filter.h#L48
fn bpf_stmt(code: u32, k: u32) -> SockFilter {
    trace!("bpf_stmt({}, {})", code, k);
    bpf_jump(code, k, 0, 0)
}

// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/filter.h#L51
fn bpf_jump(code: u32, k: u32, jt: u8, jf: u8) -> SockFilter {
    trace!("*bpf_jump({}, {}, {}, {})", code, k, jt, jf);
    SockFilter {
        code: code as u16,
        k,
        jt,
        jf,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::SockFilter;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn sock_filter_serialize_deserialize(a in 0..100, b in 0i32..10) {
            let filter = SockFilter {
                code: (a + b) as u16,
                jt: a as u8,
                jf: b as u8,
                k: (a * b) as u32,
            };
            let serialized = serde_json::to_string(&filter).unwrap();
            let deserialized: SockFilter = serde_json::from_str(&serialized).unwrap();
            prop_assert_eq!(filter, deserialized);
        }
    }
}
