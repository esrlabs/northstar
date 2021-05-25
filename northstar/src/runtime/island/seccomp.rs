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

use bindings::{
    seccomp_data, sock_filter, sock_fprog, BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET,
    BPF_W, SECCOMP_RET_ALLOW, SECCOMP_RET_KILL, SECCOMP_RET_LOG, SYSCALL_MAP,
};
use nix::errno::Errno;

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

#[cfg(all(target_arch = "aarch64"))]
const REQUIRED_SYSCALLS: &[u32] = &[bindings::SYS_execve];

#[cfg(all(target_arch = "x86_64"))]
const REQUIRED_SYSCALLS: &[u32] = &[bindings::SYS_execve];

pub struct Builder {
    allowlist: Vec<sock_filter>,
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

        // Load architecture into accumulator
        builder.allowlist.push(bpf_stmt(
            BPF_LD | BPF_W | BPF_ABS,
            memoffset::offset_of!(seccomp_data, arch) as u32,
        ));

        // Kill process if architecture does not match
        builder.allowlist.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            AUDIT_ARCH,
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
        for syscall in REQUIRED_SYSCALLS {
            builder = builder.allow_syscall_nr(*syscall as u32);
        }
        builder
    }

    /// Add syscall number to whitelist
    pub fn allow_syscall_nr(mut self, nr: u32) -> Builder {
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

    /// Add syscall name to whitelist
    pub fn allow_syscall_name(self, name: &str) -> Builder {
        let syscall_nr = translate_syscall(name).expect("Failed to translate syscall");
        self.allow_syscall_nr(syscall_nr)
    }

    /// Log syscall violations only
    #[allow(unused)]
    pub fn log_only(mut self) -> Builder {
        self.log_only = true;
        self
    }

    /// Apply seccomp rules
    pub fn apply(mut self) {
        #[cfg(target_os = "android")]
        const PR_SET_SECCOMP: nix::libc::c_int = 22;

        #[cfg(target_os = "android")]
        const SECCOMP_MODE_FILTER: nix::libc::c_int = 2;

        #[cfg(not(target_os = "android"))]
        use nix::libc::PR_SET_SECCOMP;

        #[cfg(not(target_os = "android"))]
        use nix::libc::SECCOMP_MODE_FILTER;

        if self.log_only {
            self.allowlist.push(bpf_ret(SECCOMP_RET_LOG));
        } else {
            self.allowlist.push(bpf_ret(SECCOMP_RET_KILL));
        }

        let sf_prog = sock_fprog {
            len: self.allowlist.len() as u16,
            filter: self.allowlist.as_mut_ptr(),
        };
        let sf_prog_ptr = &sf_prog as *const sock_fprog;
        let result = unsafe { nix::libc::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, sf_prog_ptr) };
        Errno::result(result)
            .map(drop)
            .expect("Failed to set seccomp filter")
    }
}

/// Get number of systemcall for a name
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
