use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::{collections::HashMap, path::PathBuf};

/// CGroups configuration
#[skip_serializing_none]
#[derive(Clone, Eq, Default, PartialEq, Debug, Serialize, Deserialize)]
pub struct CGroups {
    /// Parent CGroup. Defaults to the cgroup in the runtime configuration.
    pub parent: Option<PathBuf>,
    /// BlkIo controller
    pub blkio: Option<BlkIoResources>,
    /// Cpu controller
    pub cpu: Option<CpuResources>,
    /// Memory controller
    pub memory: Option<MemoryResources>,
}

/// Bkio device resource
#[skip_serializing_none]
#[derive(Clone, Eq, Default, PartialEq, Debug, Serialize, Deserialize)]
pub struct BlkIoDeviceResource {
    /// The major number of the device.
    pub major: u64,
    /// The minor number of the device.
    pub minor: u64,
    /// The weight of the device against the descendant nodes.
    pub weight: Option<u16>,
    /// The weight of the device against the sibling nodes.
    pub leaf_weight: Option<u16>,
}

/// Provides the ability to throttle a device (both byte/sec, and IO op/s)
#[derive(Clone, Eq, Default, PartialEq, Debug, Serialize, Deserialize)]
pub struct BlkIoDeviceThrottleResource {
    /// The major number of the device.
    pub major: u64,
    /// The minor number of the device.
    pub minor: u64,
    /// The rate.
    pub rate: u64,
}

/// Blkio controller
#[skip_serializing_none]
#[derive(Clone, Eq, Default, PartialEq, Debug, Serialize, Deserialize)]
pub struct BlkIoResources {
    /// The weight of the control group against descendant nodes.
    pub weight: Option<u16>,
    /// The weight of the control group against sibling nodes.
    pub leaf_weight: Option<u16>,
    /// For each device, a separate weight (both normal and leaf) can be provided.
    pub weight_device: Vec<BlkIoDeviceResource>,
    /// Throttled read bytes/second can be provided for each device.
    pub throttle_read_bps_device: Vec<BlkIoDeviceThrottleResource>,
    /// Throttled read IO operations per second can be provided for each device.
    pub throttle_read_iops_device: Vec<BlkIoDeviceThrottleResource>,
    /// Throttled written bytes/second can be provided for each device.
    pub throttle_write_bps_device: Vec<BlkIoDeviceThrottleResource>,
    /// Throttled write IO operations per second can be provided for each device.
    pub throttle_write_iops_device: Vec<BlkIoDeviceThrottleResource>,
    /// Customized key-value attributes
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attrs: HashMap<String, String>,
}

/// Cpu controller
#[skip_serializing_none]
#[derive(Clone, Eq, Default, PartialEq, Debug, Serialize, Deserialize)]
pub struct CpuResources {
    // cpuset
    /// A comma-separated list of CPU IDs where the task in the control group can run. Dashes
    /// between numbers indicate ranges.
    pub cpus: Option<String>,
    /// Same syntax as the `cpus` field of this structure, but applies to memory nodes instead of
    /// processors.
    pub mems: Option<String>,
    // cpu
    /// Weight of how much of the total CPU time should this control group get. Note that this is
    /// hierarchical, so this is weighted against the siblings of this control group.
    pub shares: Option<u64>,
    /// In one `period`, how much can the tasks run in nanoseconds.
    pub quota: Option<i64>,
    /// Period of time in nanoseconds.
    pub period: Option<u64>,
    /// This is currently a no-operation.
    pub realtime_runtime: Option<i64>,
    /// This is currently a no-operation.
    pub realtime_period: Option<u64>,
    /// Customized key-value attributes
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attrs: HashMap<String, String>,
}

/// Memory controller
#[skip_serializing_none]
#[derive(Clone, Eq, Default, PartialEq, Debug, Serialize, Deserialize)]
pub struct MemoryResources {
    /// Enable the northstar oom monitor. Default is off.
    #[serde(default)]
    pub oom_monitor: bool,
    /// How much memory (in bytes) can the kernel consume.
    pub kernel_memory_limit: Option<i64>,
    /// Upper limit of memory usage of the control group's tasks.
    pub memory_hard_limit: Option<i64>,
    /// How much memory the tasks in the control group can use when the system is under memory
    /// pressure.
    pub memory_soft_limit: Option<i64>,
    /// How much of the kernel's memory (in bytes) can be used for TCP-related buffers.
    pub kernel_tcp_memory_limit: Option<i64>,
    /// How much memory and swap together can the tasks in the control group use.
    pub memory_swap_limit: Option<i64>,
    /// Controls the tendency of the kernel to swap out parts of the address space of the tasks to
    /// disk. Lower value implies less likely.
    ///
    /// Note, however, that a value of zero does not mean the process is never swapped out. Use the
    /// traditional `mlock(2)` system call for that purpose.
    pub swappiness: Option<u64>,
    /// Customized key-value attributes
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attrs: HashMap<String, String>,
}
