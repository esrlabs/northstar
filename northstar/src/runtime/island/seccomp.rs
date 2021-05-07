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

#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/seccomp_bindings.rs"));
include!(concat!(env!("OUT_DIR"), "/syscall_bindings.rs"));
include!(concat!(env!("OUT_DIR"), "/audit_bindings.rs"));

pub fn translate_syscall(name: &str) -> Option<&nix::libc::c_long> {
    SYSCALL_MAP.get(name)
}

// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/filter.h
pub fn bpf_stmt(code: u32, k: u32) -> sock_filter {
    sock_filter {
        code: code as u16,
        k,
        jt: 0,
        jf: 0,
    }
}

pub fn bpf_jump(code: u32, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter {
        code: code as u16,
        k,
        jt,
        jf,
    }
}

pub fn bpf_ret(k: u32) -> sock_filter {
    bpf_stmt(BPF_RET | BPF_K, k)
}

pub type SyscallAllowlist = Vec<sock_filter>;

static REQUIRED_SYSCALLS_X86_64: &'static [nix::libc::c_long] = &[
    nix::libc::SYS_clone,
    nix::libc::SYS_mmap,
    nix::libc::SYS_prctl,
    nix::libc::SYS_munmap,
    nix::libc::SYS_mprotect,
    nix::libc::SYS_openat,
    nix::libc::SYS_close,
    nix::libc::SYS_fstat,
    nix::libc::SYS_rt_sigaction,
    nix::libc::SYS_pread64,
    nix::libc::SYS_read,
    nix::libc::SYS_execve,
    nix::libc::SYS_set_tid_address,
    nix::libc::SYS_sigaltstack,
    nix::libc::SYS_exit_group,
    nix::libc::SYS_stat,
    nix::libc::SYS_poll,
    nix::libc::SYS_brk,
    nix::libc::SYS_rt_sigprocmask,
    nix::libc::SYS_access,
    nix::libc::SYS_arch_prctl,
    nix::libc::SYS_sched_getaffinity,
    nix::libc::SYS_set_robust_list,
    nix::libc::SYS_prlimit64,
];

pub enum Architecture {
    X86_64,
}

impl Architecture {
    pub fn to_linux_value(&self) -> u32 {
        match self {
            Architecture::X86_64 => AUDIT_ARCH_X86_64,
        }
    }

    pub fn required_syscalls(&self) -> &'static [nix::libc::c_long] {
        match self {
            Architecture::X86_64 => REQUIRED_SYSCALLS_X86_64,
        }
    }
}

pub struct Builder {
    allowlist: SyscallAllowlist,
    log_violations_only: bool,
}

impl Builder {
    const EVAL_NEXT: u8 = 0;
    const SKIP_NEXT: u8 = 1;

    pub fn new(arch: Architecture) -> Self {
        let mut builder = Builder {
            allowlist: Vec::new(),
            log_violations_only: false,
        };

        // Load architecture into accumulator
        builder.allowlist.push(bpf_stmt(
            BPF_LD | BPF_W | BPF_ABS,
            memoffset::offset_of!(seccomp_data, arch) as u32,
        ));

        // Kill process if architecture does not match
        builder.allowlist.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            arch.to_linux_value(),
            Builder::SKIP_NEXT,
            Builder::EVAL_NEXT,
        ));
        builder.allowlist.push(bpf_ret(SECCOMP_RET_KILL));

        // Load system call number into accumulator for subsequent filtering
        builder.allowlist.push(bpf_stmt(
            BPF_LD | BPF_W | BPF_ABS,
            memoffset::offset_of!(seccomp_data, nr) as u32,
        ));

        // Add default allowlist for architecture
        for syscall in arch.required_syscalls() {
            builder = builder.allow_syscall(*syscall as u32);
        }
        builder
    }

    pub fn allow_syscall(mut self, nr: u32) -> Builder {
        // If syscall matches return 'allow' directly. If not, skip return instruction and go to next check.
        self.allowlist.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            nr,
            Builder::EVAL_NEXT,
            Builder::SKIP_NEXT,
        ));
        self.allowlist.push(bpf_ret(SECCOMP_RET_ALLOW));
        self
    }

    pub fn log_only(mut self) -> Builder {
        self.log_violations_only = true;
        self
    }

    pub fn build(mut self) -> SyscallAllowlist {
        if self.log_violations_only {
            self.allowlist.push(bpf_ret(SECCOMP_RET_LOG));
        } else {
            self.allowlist.push(bpf_ret(SECCOMP_RET_KILL));
        }
        self.allowlist
    }
}
