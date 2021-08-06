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
    npk::manifest::{SyscallArgRule, SyscallRule},
    runtime::island::seccomp::{builder_from_rules, Builder},
};
use std::{collections::HashMap, convert::TryInto};

// Filter lists that mimic docker's default list
// (https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

// Unconditional list of allowed syscalls
pub const SYSCALLS_BASE: &[&str] = &[
    "accept",
    "accept4",
    "access",
    "adjtimex",
    "alarm",
    "bind",
    "brk",
    "capget",
    "capset",
    "chdir",
    "chmod",
    "chown",
    "chown32",
    "clock_adjtime",
    "clock_adjtime64",
    "clock_getres",
    "clock_getres_time64",
    "clock_gettime",
    "clock_gettime64",
    "clock_nanosleep",
    "clock_nanosleep_time64",
    "close",
    "close_range",
    "connect",
    "copy_file_range",
    "creat",
    "dup",
    "dup2",
    "dup3",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_ctl_old",
    "epoll_pwait",
    "epoll_pwait2",
    "epoll_wait",
    "epoll_wait_old",
    "eventfd",
    "eventfd2",
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "faccessat",
    "faccessat2",
    "fadvise64",
    "fadvise64_64",
    "fallocate",
    "fanotify_mark",
    "fchdir",
    "fchmod",
    "fchmodat",
    "fchown",
    "fchown32",
    "fchownat",
    "fcntl",
    "fcntl64",
    "fdatasync",
    "fgetxattr",
    "flistxattr",
    "flock",
    "fork",
    "fremovexattr",
    "fsetxattr",
    "fstat",
    "fstat64",
    "fstatat64",
    "fstatfs",
    "fstatfs64",
    "fsync",
    "ftruncate",
    "ftruncate64",
    "futex",
    "futex_time64",
    "futimesat",
    "getcpu",
    "getcwd",
    "getdents",
    "getdents64",
    "getegid",
    "getegid32",
    "geteuid",
    "geteuid32",
    "getgid",
    "getgid32",
    "getgroups",
    "getgroups32",
    "getitimer",
    "getpeername",
    "getpgid",
    "getpgrp",
    "getpid",
    "getppid",
    "getpriority",
    "getrandom",
    "getresgid",
    "getresgid32",
    "getresuid",
    "getresuid32",
    "getrlimit",
    "get_robust_list",
    "getrusage",
    "getsid",
    "getsockname",
    "getsockopt",
    "get_thread_area",
    "gettid",
    "gettimeofday",
    "getuid",
    "getuid32",
    "getxattr",
    "inotify_add_watch",
    "inotify_init",
    "inotify_init1",
    "inotify_rm_watch",
    "io_cancel",
    "ioctl",
    "io_destroy",
    "io_getevents",
    "io_pgetevents",
    "io_pgetevents_time64",
    "ioprio_get",
    "ioprio_set",
    "io_setup",
    "io_submit",
    "io_uring_enter",
    "io_uring_register",
    "io_uring_setup",
    "ipc",
    "kill",
    "lchown",
    "lchown32",
    "lgetxattr",
    "link",
    "linkat",
    "listen",
    "listxattr",
    "llistxattr",
    "_llseek",
    "lremovexattr",
    "lseek",
    "lsetxattr",
    "lstat",
    "lstat64",
    "madvise",
    "membarrier",
    "memfd_create",
    "mincore",
    "mkdir",
    "mkdirat",
    "mknod",
    "mknodat",
    "mlock",
    "mlock2",
    "mlockall",
    "mmap",
    "mmap2",
    "mprotect",
    "mq_getsetattr",
    "mq_notify",
    "mq_open",
    "mq_timedreceive",
    "mq_timedreceive_time64",
    "mq_timedsend",
    "mq_timedsend_time64",
    "mq_unlink",
    "mremap",
    "msgctl",
    "msgget",
    "msgrcv",
    "msgsnd",
    "msync",
    "munlock",
    "munlockall",
    "munmap",
    "nanosleep",
    "newfstatat",
    "_newselect",
    "open",
    "openat",
    "openat2",
    "pause",
    "pidfd_open",
    "pidfd_send_signal",
    "pipe",
    "pipe2",
    "poll",
    "ppoll",
    "ppoll_time64",
    "prctl",
    "pread64",
    "preadv",
    "preadv2",
    "prlimit64",
    "pselect6",
    "pselect6_time64",
    "pwrite64",
    "pwritev",
    "pwritev2",
    "read",
    "readahead",
    "readlink",
    "readlinkat",
    "readv",
    "recv",
    "recvfrom",
    "recvmmsg",
    "recvmmsg_time64",
    "recvmsg",
    "remap_file_pages",
    "removexattr",
    "rename",
    "renameat",
    "renameat2",
    "restart_syscall",
    "rmdir",
    "rseq",
    "rt_sigaction",
    "rt_sigpending",
    "rt_sigprocmask",
    "rt_sigqueueinfo",
    "rt_sigreturn",
    "rt_sigsuspend",
    "rt_sigtimedwait",
    "rt_sigtimedwait_time64",
    "rt_tgsigqueueinfo",
    "sched_getaffinity",
    "sched_getattr",
    "sched_getparam",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_getscheduler",
    "sched_rr_get_interval",
    "sched_rr_get_interval_time64",
    "sched_setaffinity",
    "sched_setattr",
    "sched_setparam",
    "sched_setscheduler",
    "sched_yield",
    "seccomp",
    "select",
    "semctl",
    "semget",
    "semop",
    "semtimedop",
    "semtimedop_time64",
    "send",
    "sendfile",
    "sendfile64",
    "sendmmsg",
    "sendmsg",
    "sendto",
    "setfsgid",
    "setfsgid32",
    "setfsuid",
    "setfsuid32",
    "setgid",
    "setgid32",
    "setgroups",
    "setgroups32",
    "setitimer",
    "setpgid",
    "setpriority",
    "setregid",
    "setregid32",
    "setresgid",
    "setresgid32",
    "setresuid",
    "setresuid32",
    "setreuid",
    "setreuid32",
    "setrlimit",
    "set_robust_list",
    "setsid",
    "setsockopt",
    "set_thread_area",
    "set_tid_address",
    "setuid",
    "setuid32",
    "setxattr",
    "shmat",
    "shmctl",
    "shmdt",
    "shmget",
    "shutdown",
    "sigaltstack",
    "signalfd",
    "signalfd4",
    "sigprocmask",
    "sigreturn",
    "socket",
    "socketcall",
    "socketpair",
    "splice",
    "stat",
    "stat64",
    "statfs",
    "statfs64",
    "statx",
    "symlink",
    "symlinkat",
    "sync",
    "sync_file_range",
    "syncfs",
    "sysinfo",
    "tee",
    "tgkill",
    "time",
    "timer_create",
    "timer_delete",
    "timer_getoverrun",
    "timer_gettime",
    "timer_gettime64",
    "timer_settime",
    "timer_settime64",
    "timerfd_create",
    "timerfd_gettime",
    "timerfd_gettime64",
    "timerfd_settime",
    "timerfd_settime64",
    "times",
    "tkill",
    "truncate",
    "truncate64",
    "ugetrlimit",
    "umask",
    "uname",
    "unlink",
    "unlinkat",
    "utime",
    "utimensat",
    "utimensat_time64",
    "utimes",
    "vfork",
    "vmsplice",
    "wait4",
    "waitid",
    "waitpid",
    "write",
    "writev",
    "process_vm_readv",  // "minKernel": "4.8"
    "process_vm_writev", // "minKernel": "4.8"
    "ptrace",            // "minKernel": "4.8"
    // Parameter condition: index=0, value={0x00, 0x08, 0x20000, 0x20008, 0xFFFFFFFF}, op=SCMP_CMP_EQ
    // (https://github.com/moby/moby/blob/20.10/profiles/seccomp/default.json#L414)
    "personality",
    #[cfg(target_arch = "aarch64")]
    "arm_fadvise64_64",
    #[cfg(target_arch = "aarch64")]
    "arm_sync_file_range",
    #[cfg(target_arch = "aarch64")]
    "sync_file_range2",
    #[cfg(target_arch = "aarch64")]
    "breakpoint",
    #[cfg(target_arch = "aarch64")]
    "cacheflush",
    #[cfg(target_arch = "aarch64")]
    "set_tls",
    #[cfg(target_arch = "x86_64")]
    "arch_prctl", // only on "amd64" and "x32"
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    "modify_ldt", // only on "amd64", "x32" and "x86"
];

// syscalls to be added if a given capability is present
pub const SYSCALLS_CAP_DAC_READ_SEARCH: &[&str] = &["open_by_handle_at"];
pub const SYSCALLS_CAP_SYS_ADMIN: &[&str] = &[
    "bpf",
    "clone",
    "fanotify_init",
    "fsconfig",
    "fsmount",
    "fsopen",
    "fspick",
    "lookup_dcookie",
    "mount",
    "move_mount",
    "name_to_handle_at",
    "open_tree",
    "perf_event_open",
    "quotactl",
    "setdomainname",
    "sethostname",
    "setns",
    "syslog",
    "umount",
    "umount2",
    "unshare",
];
pub const SYSCALLS_CAP_SYS_BOOT: &[&str] = &["reboot"];
pub const SYSCALLS_CAP_SYS_CHROOT: &[&str] = &["chroot"];
pub const SYSCALLS_CAP_SYS_MODULE: &[&str] = &["delete_module", "init_module", "finit_module"];
pub const SYSCALLS_CAP_SYS_PACCT: &[&str] = &["acct"];
pub const SYSCALLS_CAP_SYS_PTRACE: &[&str] = &[
    "kcmp",
    "pidfd_getfd",
    "process_madvise",
    "process_vm_readv",
    "process_vm_writev",
    "ptrace",
];
pub const SYSCALLS_CAP_SYS_RAWIO: &[&str] = &["iopl", "ioperm"];
pub const SYSCALLS_CAP_SYS_TIME: &[&str] = &["settimeofday", "stime", "clock_settime"];
pub const SYSCALLS_CAP_SYS_TTY_CONFIG: &[&str] = &["vhangup"];
pub const SYSCALLS_CAP_SYS_NICE: &[&str] = &["get_mempolicy", "mbind", "set_mempolicy"];
pub const SYSCALLS_CAP_SYSLOG: &[&str] = &["syslog"];

// syscalls to be added if a given capability is _missing_
pub const SYSCALLS_NON_CAP_SYS_ADMIN: &[&str] = &[
    // Parameter condition: index=0, value=0x7E020000, op=SCMP_CMP_MASKED_EQ
    // (https://github.com/moby/moby/blob/20.10/profiles/seccomp/default.json#L624)
    "clone",
];

// pre-computed builders
lazy_static::lazy_static! {
    pub static ref BASE: Builder = {
        let mut hm: HashMap<NonNullString, SyscallRule> = HashMap::with_capacity(SYSCALLS_BASE.len());
        for name in SYSCALLS_BASE {
            // Parameter condition: index=0, value={0x00, 0x08, 0x20000, 0x20008, 0xFFFFFFFF}, op=SCMP_CMP_EQ
            // (https://github.com/moby/moby/blob/20.10/profiles/seccomp/default.json#L414)
            if *name == "personality" {
                hm.insert(name.to_string().try_into().unwrap(), SyscallRule::Args(SyscallArgRule{
                    index: 0,
                    values: Some([0x00, 0x08, 0x20000, 0x20008, 0xFFFFFFFF].to_vec()),
                    mask: None}));
            }
            else {
                hm.insert(name.to_string().try_into().unwrap(), SyscallRule::All);
            }
        }
        builder_from_rules(&hm)
    };
}

lazy_static::lazy_static! {
    pub static ref CAP_DAC_READ_SEARCH: Builder = {
        let mut hm: HashMap<NonNullString, SyscallRule> = HashMap::with_capacity(SYSCALLS_CAP_DAC_READ_SEARCH.len());
        for name in SYSCALLS_CAP_DAC_READ_SEARCH {
            hm.insert(name.to_string().try_into().unwrap(), SyscallRule::All);
        }
        builder_from_rules(&hm)
    };
}

lazy_static::lazy_static! {
    pub static ref CAP_SYS_ADMIN: Builder = {
        let mut hm: HashMap<NonNullString, SyscallRule> = HashMap::with_capacity(SYSCALLS_CAP_SYS_ADMIN.len());
        for name in SYSCALLS_CAP_SYS_ADMIN {
            hm.insert(name.to_string().try_into().unwrap(), SyscallRule::All);
        }
        builder_from_rules(&hm)
    };
}

lazy_static::lazy_static! {
    pub static ref CAP_SYS_BOOT: Builder = {
        let mut hm: HashMap<NonNullString, SyscallRule> = HashMap::with_capacity(SYSCALLS_CAP_SYS_BOOT.len());
        for name in SYSCALLS_CAP_SYS_BOOT {
            hm.insert(name.to_string().try_into().unwrap(), SyscallRule::All);
        }
        builder_from_rules(&hm)
    };
}

lazy_static::lazy_static! {
    pub static ref CAP_SYS_CHROOT: Builder = {
        let mut hm: HashMap<NonNullString, SyscallRule> = HashMap::with_capacity(SYSCALLS_CAP_SYS_CHROOT.len());
        for name in SYSCALLS_CAP_SYS_CHROOT {
            hm.insert(name.to_string().try_into().unwrap(), SyscallRule::All);
        }
        builder_from_rules(&hm)
    };
}

lazy_static::lazy_static! {
    pub static ref CAP_SYS_MODULE: Builder = {
        let mut hm: HashMap<NonNullString, SyscallRule> = HashMap::with_capacity(SYSCALLS_CAP_SYS_MODULE.len());
        for name in SYSCALLS_CAP_SYS_MODULE {
            hm.insert(name.to_string().try_into().unwrap(), SyscallRule::All);
        }
        builder_from_rules(&hm)
    };
}

lazy_static::lazy_static! {
    pub static ref CAP_SYS_PACCT: Builder = {
        let mut hm: HashMap<NonNullString, SyscallRule> = HashMap::with_capacity(SYSCALLS_CAP_SYS_PACCT.len());
        for name in SYSCALLS_CAP_SYS_PACCT {
            hm.insert(name.to_string().try_into().unwrap(), SyscallRule::All);
        }
        builder_from_rules(&hm)
    };
}

lazy_static::lazy_static! {
    pub static ref CAP_SYS_PTRACE: Builder = {
        let mut hm: HashMap<NonNullString, SyscallRule> = HashMap::with_capacity(SYSCALLS_CAP_SYS_PTRACE.len());
        for name in SYSCALLS_CAP_SYS_PTRACE {
            hm.insert(name.to_string().try_into().unwrap(), SyscallRule::All);
        }
        builder_from_rules(&hm)
    };
}

lazy_static::lazy_static! {
    pub static ref CAP_SYS_RAWIO: Builder = {
        let mut hm: HashMap<NonNullString, SyscallRule> = HashMap::with_capacity(SYSCALLS_CAP_SYS_RAWIO.len());
        for name in SYSCALLS_CAP_SYS_RAWIO {
            hm.insert(name.to_string().try_into().unwrap(), SyscallRule::All);
        }
        builder_from_rules(&hm)
    };
}

lazy_static::lazy_static! {
    pub static ref CAP_SYS_TIME: Builder = {
        let mut hm: HashMap<NonNullString, SyscallRule> = HashMap::with_capacity(SYSCALLS_CAP_SYS_TIME.len());
        for name in SYSCALLS_CAP_SYS_TIME {
            hm.insert(name.to_string().try_into().unwrap(), SyscallRule::All);
        }
        builder_from_rules(&hm)
    };
}

lazy_static::lazy_static! {
    pub static ref CAP_SYS_TTY_CONFIG: Builder = {
        let mut hm: HashMap<NonNullString, SyscallRule> = HashMap::with_capacity(SYSCALLS_CAP_SYS_TTY_CONFIG.len());
        for name in SYSCALLS_CAP_SYS_TTY_CONFIG {
            hm.insert(name.to_string().try_into().unwrap(), SyscallRule::All);
        }
        builder_from_rules(&hm)
    };
}

lazy_static::lazy_static! {
    pub static ref CAP_SYS_NICE: Builder = {
        let mut hm: HashMap<NonNullString, SyscallRule> = HashMap::with_capacity(SYSCALLS_CAP_SYS_NICE.len());
        for name in SYSCALLS_CAP_SYS_NICE {
            hm.insert(name.to_string().try_into().unwrap(), SyscallRule::All);
        }
        builder_from_rules(&hm)
    };
}

lazy_static::lazy_static! {
    pub static ref CAP_SYSLOG: Builder = {
        let mut hm: HashMap<NonNullString, SyscallRule> = HashMap::with_capacity(SYSCALLS_CAP_SYSLOG.len());
        for name in SYSCALLS_CAP_SYSLOG {
            hm.insert(name.to_string().try_into().unwrap(), SyscallRule::All);
        }
        builder_from_rules(&hm)
    };
}

lazy_static::lazy_static! {
    pub static ref NON_CAP_SYS_ADMIN: Builder = {
        let mut hm: HashMap<NonNullString, SyscallRule> = HashMap::with_capacity(SYSCALLS_NON_CAP_SYS_ADMIN.len());
        for name in SYSCALLS_NON_CAP_SYS_ADMIN {
            if *name == "clone" {
                // Parameter condition: index=0, value=0x7E020000, op=SCMP_CMP_MASKED_EQ
                // (https://github.com/moby/moby/blob/20.10/profiles/seccomp/default.json#L624)
                hm.insert(name.to_string().try_into().unwrap(), SyscallRule::Args(SyscallArgRule{
                    index: 0,
                    values: None,
                    // Docker allows a masked syscall argument only if it is equal to 0.
                    // This effectively prohibits the use of the bits covered by the mask. Since our
                    // logic specifically allows arguments that match the mask, we invert the
                    // bitmask of docker here to achieve the same behavior.
                    mask: Some(!0x7E020000)}));
            }
        }
        builder_from_rules(&hm)
    };
}
