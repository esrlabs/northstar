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

pub struct Builder {
    allowlist: SyscallAllowlist,
    log_violations_only: bool,
}

impl Builder {
    pub fn new() -> Self {
        let mut builder = Builder {
            allowlist: Vec::new(),
            log_violations_only: false,
        };

        // Load system call number into accumulator
        builder.allowlist.push(bpf_stmt(
            BPF_LD | BPF_W | BPF_ABS,
            memoffset::offset_of!(seccomp_data, nr) as u32,
        ));
        builder
    }

    pub fn allow_syscall(mut self, nr: u32) -> Builder {
        // If syscall matches return allow directly. If not, go to next instruction.
        self.allowlist
            .push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
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
