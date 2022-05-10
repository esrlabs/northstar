use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Linux capability
#[derive(Clone, Eq, Hash, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[allow(non_camel_case_types)]
pub enum Capability {
    /// `CAP_CHOWN` (from POSIX)
    CAP_CHOWN,
    /// `CAP_DAC_OVERRIDE` (from POSIX)
    CAP_DAC_OVERRIDE,
    /// `CAP_DAC_READ_SEARCH` (from POSIX)
    CAP_DAC_READ_SEARCH,
    /// `CAP_FOWNER` (from POSIX)
    CAP_FOWNER,
    /// `CAP_FSETID` (from POSIX)
    CAP_FSETID,
    /// `CAP_KILL` (from POSIX)
    CAP_KILL,
    /// `CAP_SETGID` (from POSIX)
    CAP_SETGID,
    /// `CAP_SETUID` (from POSIX)
    CAP_SETUID,
    /// `CAP_SETPCAP` (from Linux)
    CAP_SETPCAP,
    /// `CAP_LINUX_IMMUTABLE` (from Linux)
    CAP_LINUX_IMMUTABLE,
    /// `CAP_NET_BIND_SERVICE` (from Linux)
    CAP_NET_BIND_SERVICE,
    /// `CAP_NET_BROADCAST` (from Linux)
    CAP_NET_BROADCAST,
    /// `CAP_NET_ADMIN` (from Linux)
    CAP_NET_ADMIN,
    /// `CAP_NET_RAW` (from Linux)
    CAP_NET_RAW,
    /// `CAP_IPC_LOCK` (from Linux)
    CAP_IPC_LOCK,
    /// `CAP_IPC_OWNER` (from Linux)
    CAP_IPC_OWNER,
    /// `CAP_SYS_MODULE` (from Linux)
    CAP_SYS_MODULE,
    /// `CAP_SYS_RAWIO` (from Linux)
    CAP_SYS_RAWIO,
    /// `CAP_SYS_CHROOT` (from Linux)
    CAP_SYS_CHROOT,
    /// `CAP_SYS_PTRACE` (from Linux)
    CAP_SYS_PTRACE,
    /// `CAP_SYS_PACCT` (from Linux)
    CAP_SYS_PACCT,
    /// `CAP_SYS_ADMIN` (from Linux)
    CAP_SYS_ADMIN,
    /// `CAP_SYS_BOOT` (from Linux)
    CAP_SYS_BOOT,
    /// `CAP_SYS_NICE` (from Linux)
    CAP_SYS_NICE,
    /// `CAP_SYS_RESOURCE` (from Linux)
    CAP_SYS_RESOURCE,
    /// `CAP_SYS_TIME` (from Linux)
    CAP_SYS_TIME,
    /// `CAP_SYS_TTY_CONFIG` (from Linux)
    CAP_SYS_TTY_CONFIG,
    /// `CAP_SYS_MKNOD` (from Linux, >= 2.4)
    CAP_MKNOD,
    /// `CAP_LEASE` (from Linux, >= 2.4)
    CAP_LEASE,
    /// `CAP_AUDIT_WRITE`
    CAP_AUDIT_WRITE,
    /// `CAP_AUDIT_CONTROL` (from Linux, >= 2.6.11)
    CAP_AUDIT_CONTROL,
    /// `CAP_SETFCAP`
    CAP_SETFCAP,
    /// `CAP_MAC_OVERRIDE`
    CAP_MAC_OVERRIDE,
    /// `CAP_MAC_ADMIN`
    CAP_MAC_ADMIN,
    /// `CAP_SYSLOG` (from Linux, >= 2.6.37)
    CAP_SYSLOG,
    /// `CAP_WAKE_ALARM` (from Linux, >= 3.0)
    CAP_WAKE_ALARM,
    /// `CAP_BLOCK_SUSPEND`
    CAP_BLOCK_SUSPEND,
    /// `CAP_AUDIT_READ` (from Linux, >= 3.16).
    CAP_AUDIT_READ,
    /// `CAP_PERFMON` (from Linux, >= 5.8).
    CAP_PERFMON,
    /// `CAP_BPF` (from Linux, >= 5.8).
    CAP_BPF,
    /// `CAP_CHECKPOINT_RESTORE` (from Linux, >= 5.9).
    CAP_CHECKPOINT_RESTORE,
}
