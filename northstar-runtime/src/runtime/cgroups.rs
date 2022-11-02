use super::{
    events::EventTx,
    runtime::Pid,
    stats::{to_value, ContainerStats},
};
use crate::{
    common::container::Container,
    npk::manifest,
    runtime::events::{CGroupEvent, ContainerEvent, Event, MemoryEvent},
};
use anyhow::{Context, Result};
use cgroups_rs::{
    memory::MemController, BlkIoDeviceResource, BlkIoDeviceThrottleResource, BlkIoResources,
    Controller, CpuResources, Hierarchy, MemoryResources,
};
use futures::stream::StreamExt;
use inotify::{Inotify, WatchMask};
use log::{debug, info, warn};
use std::{collections::HashMap, fmt::Debug, os::unix::io::AsRawFd, path::Path};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    select,
    sync::mpsc::error::TrySendError,
    task::{self, JoinHandle},
    time,
};
use tokio_eventfd::EventFd;
use tokio_util::sync::CancellationToken;

/// Default runtime hierarchy that yields only implemented and supported controllers
/// instead of the default list.
fn hierarchy() -> Box<dyn Hierarchy> {
    Box::new(RuntimeHierarchy::new())
}

/// Create the top level cgroups used by northstar
pub async fn init(name: &Path) -> Result<()> {
    // TODO: Add check for supported controllers

    info!("Initializing cgroups with name {}", name.display());
    let cgroup = cgroups_rs::Cgroup::new(hierarchy(), name);
    debug!(
        "Using cgroups version {}",
        if cgroup.v2() { "2" } else { "1" }
    );
    Ok(())
}

/// Shutdown the cgroups config by removing the dir
pub async fn shutdown(dir: &Path) -> Result<()> {
    cgroups_rs::Cgroup::new(hierarchy(), dir)
        .delete()
        .with_context(|| format!("failed to delete {} cgroup", dir.display()))
}

/// Implement a custom type for Hierarchy that filters subsystems
#[derive(Debug)]
struct RuntimeHierarchy {
    inner: Box<dyn Hierarchy>,
}

impl RuntimeHierarchy {
    /// Create a new instance
    fn new() -> RuntimeHierarchy {
        RuntimeHierarchy {
            inner: cgroups_rs::hierarchies::auto(),
        }
    }
}

impl Hierarchy for RuntimeHierarchy {
    /// Filter unimplemented controllers
    fn subsystems(&self) -> Vec<cgroups_rs::Subsystem> {
        self.inner
            .subsystems()
            .drain(..)
            .filter(|s| match s {
                cgroups_rs::Subsystem::Pid(_) => false,
                cgroups_rs::Subsystem::Mem(_) => true,
                cgroups_rs::Subsystem::CpuSet(_) => false,
                cgroups_rs::Subsystem::CpuAcct(_) => true,
                cgroups_rs::Subsystem::Cpu(_) => true,
                cgroups_rs::Subsystem::Devices(_) => false,
                cgroups_rs::Subsystem::Freezer(_) => false,
                cgroups_rs::Subsystem::NetCls(_) => false,
                cgroups_rs::Subsystem::BlkIo(_) => true,
                cgroups_rs::Subsystem::PerfEvent(_) => false,
                cgroups_rs::Subsystem::NetPrio(_) => false,
                cgroups_rs::Subsystem::HugeTlb(_) => false,
                cgroups_rs::Subsystem::Rdma(_) => false,
                cgroups_rs::Subsystem::Systemd(_) => false,
            })
            .collect()
    }

    fn root(&self) -> std::path::PathBuf {
        self.inner.root()
    }

    fn root_control_group(&self) -> cgroups_rs::Cgroup {
        self.inner.root_control_group()
    }

    fn v2(&self) -> bool {
        self.inner.v2()
    }
}

#[derive(Debug)]
pub struct CGroups {
    container: Container,
    cgroup: cgroups_rs::Cgroup,
    memory_monitor: MemoryMonitor,
}

impl CGroups {
    pub(super) async fn new(
        top_level_dir: &str,
        tx: EventTx,
        container: &Container,
        config: &manifest::cgroups::CGroups,
        pid: Pid,
    ) -> Result<CGroups> {
        debug!("Creating cgroups for {}", container);
        let name: &str = container.name().as_ref();
        let cgroup: cgroups_rs::Cgroup =
            cgroups_rs::Cgroup::new(hierarchy(), Path::new(top_level_dir).join(name));

        let resources = cgroups_rs::Resources {
            memory: config.memory.clone().map(Into::into).unwrap_or_default(),
            pid: cgroups_rs::PidResources::default(),
            cpu: config.cpu.clone().map(Into::into).unwrap_or_default(),
            devices: cgroups_rs::DeviceResources::default(),
            network: cgroups_rs::NetworkResources::default(),
            hugepages: cgroups_rs::HugePageResources::default(),
            blkio: config.blkio.clone().map(Into::into).unwrap_or_default(),
        };

        cgroup
            .apply(&resources)
            .context("failed to configure cgroups")?;

        // If adding the task fails it's a fault of the runtime or it's integration
        // and not of the container
        cgroup
            .add_task(cgroups_rs::CgroupPid::from(pid as u64))
            .expect("failed to assign pid");

        let memory_controller = cgroup
            .controller_of::<MemController>()
            .expect("failed to get memory controller");
        let memory_path = memory_controller.path();
        let memory_monitor = if cgroup.v2() {
            MemoryMonitor::new_v2(container.clone(), memory_path, tx).await
        } else {
            MemoryMonitor::new_v1(container.clone(), memory_path, tx).await
        };

        Ok(CGroups {
            container: container.clone(),
            cgroup,
            memory_monitor,
        })
    }

    pub async fn destroy(self) {
        debug!("Stopping oom monitor of {}", self.container);
        self.memory_monitor.stop().await;

        info!("Destroying cgroup of {}", self.container);
        assert!(self.cgroup.tasks().is_empty());
        self.cgroup.delete().expect("failed to remove cgroups");
    }

    /// Gather statistics from controllers
    pub(super) fn stats(&self) -> ContainerStats {
        let mut stats = HashMap::new();
        for c in self.cgroup.subsystems() {
            match c {
                cgroups_rs::Subsystem::BlkIo(c) => {
                    stats.insert("blkio".into(), to_value(c.blkio()).unwrap_or_default());
                }
                cgroups_rs::Subsystem::Cpu(c) => {
                    stats.insert("cpu".into(), to_value(c.cpu()).unwrap_or_default());
                }
                cgroups_rs::Subsystem::Mem(c) => {
                    let mut memory = HashMap::new();
                    memory.insert(
                        "memory".to_string(),
                        to_value(c.memory_stat()).unwrap_or_default(),
                    );
                    memory.insert(
                        "kmem".to_string(),
                        to_value(c.kmem_stat()).unwrap_or_default(),
                    );
                    memory.insert(
                        "kmem_tcp".to_string(),
                        to_value(c.kmem_tcp_stat()).unwrap_or_default(),
                    );
                    stats.insert("memory".to_string(), to_value(memory).unwrap_or_default());
                }
                _ => (),
            }
        }

        stats
    }
}

#[derive(Debug)]
struct MemoryMonitor {
    token: CancellationToken,
    task: JoinHandle<()>,
}

impl MemoryMonitor {
    /// Setup an event fd and oom event listening.
    async fn new_v1(container: Container, path: &Path, tx: EventTx) -> MemoryMonitor {
        const OOM_CONTROL: &str = "memory.oom_control";
        const EVENT_CONTROL: &str = "cgroup.event_control";

        // Configure oom
        let oom_control = path.join(OOM_CONTROL);
        let event_control = path.join(EVENT_CONTROL);
        let token = CancellationToken::new();

        let mut event_fd = EventFd::new(0, false).expect("failed to create eventfd");

        debug!("Opening oom_control: {}", oom_control.display());
        let oom_control = fs::OpenOptions::new()
            .write(true)
            .open(&oom_control)
            .await
            .expect("failed to open oom_control");

        debug!("Opening event_control: {}", event_control.display());
        let mut event_control = fs::OpenOptions::new()
            .write(true)
            .open(&event_control)
            .await
            .expect("failed to open event_control");
        event_control
            .write_all(format!("{} {}", event_fd.as_raw_fd(), oom_control.as_raw_fd()).as_bytes())
            .await
            .expect("failed to setup event_control");
        event_control
            .flush()
            .await
            .expect("failed to setup oom event fd");

        // This task stops when the main loop receiver closes
        let task = {
            let stop = token.clone();
            task::spawn(async move {
                debug!("Listening for v1 oom events of {}", container);
                let mut buffer = [0u8; 16];

                'outer: loop {
                    select! {
                        _ = stop.cancelled() => break 'outer,
                        _ = tx.closed() => break 'outer,
                        _ = event_fd.read(&mut buffer) => {
                            'inner: loop {
                                warn!("Process {} is out of memory", container);
                                let event = Event::Container(container.clone(), ContainerEvent::CGroup(CGroupEvent::Memory(MemoryEvent {
                                    oom: Some(1),
                                    ..Default::default()
                                })));
                                match tx.try_send(event) {
                                    Ok(_) => break 'inner,
                                    Err(TrySendError::Closed(_)) => break 'outer,
                                    Err(TrySendError::Full(_)) => time::sleep(time::Duration::from_millis(1)).await,
                                }
                            }
                        }
                    }
                }
                drop(event_control);
                drop(oom_control);
                drop(event_fd);
            })
        };

        MemoryMonitor { token, task }
    }

    /// Construct a new cgroups v2 memory monitor
    async fn new_v2(container: Container, path: &Path, tx: EventTx) -> MemoryMonitor {
        const MEMORY_EVENTS: &str = "memory.events";

        let token = CancellationToken::new();
        let path = path.join(MEMORY_EVENTS);

        // This task stops when the main loop receiver closes
        let task = {
            let stop = token.clone();
            let mut inotify = Inotify::init().expect("Error while initializing inotify instance");

            inotify
                .add_watch(&path, WatchMask::MODIFY)
                .expect("failed to add file watch");

            task::spawn(async move {
                debug!("Listening for v2 oom events of {}", container);

                let mut buffer = [0; 1024];
                let mut stream = inotify
                    .event_stream(&mut buffer)
                    .expect("failed to initialize inotify event stream");

                'outer: loop {
                    select! {
                        _ = stop.cancelled() => break 'outer,
                        _ = tx.closed() => break 'outer,
                        _ = stream.next() => {
                            let events = fs::read_to_string(&path).await.expect("failed to read memory events");
                            let event = parse_cgroups_event(&events);
                            'inner: loop {
                                let event = Event::Container(container.clone(), ContainerEvent::CGroup(event.clone()));
                                warn!("Process {} is out of memory", container);
                                match tx.try_send(event) {
                                    Ok(_) => break 'inner,
                                    Err(TrySendError::Closed(_)) => break 'outer,
                                    Err(TrySendError::Full(_)) => time::sleep(time::Duration::from_millis(1)).await,
                                }
                            }
                        }
                    }
                }
            })
        };

        MemoryMonitor { token, task }
    }

    /// Stop the monitor and wait for the task termination
    async fn stop(self) {
        self.token.cancel();
        self.task.await.expect("Task error");
    }
}

/// Parse the cgroup v2 memory.events file
fn parse_cgroups_event(s: &str) -> CGroupEvent {
    let mut event = MemoryEvent::default();
    for line in s.lines() {
        let mut iter = line.split_whitespace().rev();
        let value = iter.next().and_then(|s| s.parse::<u64>().ok());
        match iter.next() {
            Some("low") => event.low = value,
            Some("high") => event.high = value,
            Some("max") => event.max = value,
            Some("oom") => event.oom = value,
            Some("oom_kill") => event.oom_kill = value,
            Some(_) | None => panic!("invalid content of memory.events"),
        }
    }
    CGroupEvent::Memory(event)
}

impl From<manifest::cgroups::CpuResources> for CpuResources {
    fn from(v: manifest::cgroups::CpuResources) -> Self {
        CpuResources {
            cpus: v.cpus,
            mems: v.mems,
            shares: v.shares,
            quota: v.quota,
            period: v.period,
            realtime_runtime: v.realtime_runtime,
            realtime_period: v.realtime_period,
            attrs: v.attrs,
        }
    }
}

impl From<manifest::cgroups::MemoryResources> for MemoryResources {
    fn from(v: manifest::cgroups::MemoryResources) -> Self {
        MemoryResources {
            kernel_memory_limit: v.kernel_memory_limit,
            memory_hard_limit: v.memory_hard_limit,
            memory_soft_limit: v.memory_soft_limit,
            kernel_tcp_memory_limit: v.kernel_tcp_memory_limit,
            memory_swap_limit: v.memory_swap_limit,
            swappiness: v.swappiness,
            attrs: v.attrs,
        }
    }
}

impl From<manifest::cgroups::BlkIoResources> for BlkIoResources {
    fn from(v: manifest::cgroups::BlkIoResources) -> Self {
        BlkIoResources {
            weight: v.weight,
            leaf_weight: v.leaf_weight,
            weight_device: v.weight_device.into_iter().map(Into::into).collect(),
            throttle_read_bps_device: v
                .throttle_read_bps_device
                .into_iter()
                .map(Into::into)
                .collect(),
            throttle_read_iops_device: v
                .throttle_read_iops_device
                .into_iter()
                .map(Into::into)
                .collect(),
            throttle_write_bps_device: v
                .throttle_write_bps_device
                .into_iter()
                .map(Into::into)
                .collect(),
            throttle_write_iops_device: v
                .throttle_write_iops_device
                .into_iter()
                .map(Into::into)
                .collect(),
            attrs: HashMap::with_capacity(0),
        }
    }
}

impl From<manifest::cgroups::BlkIoDeviceResource> for BlkIoDeviceResource {
    fn from(v: manifest::cgroups::BlkIoDeviceResource) -> Self {
        BlkIoDeviceResource {
            major: v.major,
            minor: v.minor,
            weight: v.weight,
            leaf_weight: v.leaf_weight,
        }
    }
}

impl From<manifest::cgroups::BlkIoDeviceThrottleResource> for BlkIoDeviceThrottleResource {
    fn from(v: manifest::cgroups::BlkIoDeviceThrottleResource) -> Self {
        BlkIoDeviceThrottleResource {
            major: v.major,
            minor: v.minor,
            rate: v.rate,
        }
    }
}
