use serde::{Deserialize, Serialize};

/// Resource limits. See setrlimit(2)
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all(serialize = "lowercase", deserialize = "lowercase"))]
pub enum RLimitResource {
    /// Address space
    AS,
    /// Maximum size of core file
    CORE,
    /// CPU time limit in seconds
    CPU,
    /// The maximum size of the process's data segment (initialized data,
    /// uninitialized data, and heap).
    DATA,
    /// The maximum size of files that the process may create
    FSIZE,
    /// A limit on the combined number of flock(2) locks and fcntl(2) leases that
    /// this process may establish.
    LOCKS,
    /// The maximum number of bytes of memory that may be locked into RAM
    MEMLOCK,
    /// Specifies the limit on the number of bytes that can be allocated for
    /// POSIX message queues for the real user ID of the calling process
    MSGQUEUE,
    /// Specifies a ceiling to which the process's nice value can be raised using
    /// setpriority(2) or nice(2)
    NICE,
    /// Specifies a value one greater than the maximum file descriptor number
    /// that can be opened by this process
    NOFILE,
    /// The maximum number of processes (or, more precisely on Linux, threads)
    /// that can be created for the real user ID of the calling process
    NPROC,
    /// Specifies the limit (in pages) of the process's resident set (the number
    /// of virtual pages resident in RAM)
    RSS,
    /// Specifies a ceiling on the real-time priority that may be set for this
    /// process using sched_setscheduler(2) and sched_setparam(2).
    RTPRIO,
    /// Specifies a limit (in microseconds) on the amount of CPU time that a
    /// process scheduled under a real-time scheduling policy may consume without
    /// making a blocking system call
    #[cfg(not(target_os = "android"))]
    RTTIME,
    /// Specifies the limit on the number of signals that may be queued for the
    /// real user ID of the calling process
    SIGPENDING,
    /// The maximum size of the process stack, in bytes. Upon reaching this
    /// limit, a SIGSEGV signal is generated
    STACK,
}

/// Value for a rlimit setting
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct RLimitValue {
    /// Soft limit value for resource. None indicates `unlimited`.
    pub soft: Option<u64>,
    /// Hard limit value for resource. None indicates `unlimited`.
    pub hard: Option<u64>,
}
