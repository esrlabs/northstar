// Copyright (c) 2019 - 2020 ESRLabs
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

use crate::{npk::Container, Event, EventTx, TerminationReason, SETTINGS, SYSTEM_GID, SYSTEM_UID};
use anyhow::{anyhow, Context, Result};
use async_std::{fs, io, prelude::*, sync, task};
use futures::{future::FutureExt, select, StreamExt};
use log::*;
use minijail::LogPriority;
use nix::{
    sys::{signal, signal::Signal, wait, wait::WaitStatus},
    unistd::Pid,
};
use north_common::manifest::Resource;
use std::{future::Future, os::unix::io::AsRawFd, time, time::Duration};
use stop_token::StopSource;

const ENV_DATA: &str = "DATA";
const ENV_NAME: &str = "NAME";
const ENV_VERSION: &str = "VERSION";

#[derive(Debug)]
pub enum ExitStatus {
    Exit(i32),
    Killed,
}

// Capture output of a child process. Create a fifo and spawn a task that forwards each line to
// the main loop. When this struct is dropped the internal spawned tasks are stopped.
#[derive(Debug)]
struct CaptureOutput {
    // Stop token to interrupt the stream
    stop_source: StopSource,
    // Fd
    fd: i32,
    // File instance to the write part. The raw fd of File is passed to minijail
    // and File must be kept in scope to avoid that it is closed.
    write: std::fs::File,
}

impl CaptureOutput {
    pub async fn new(
        tmpdir: &std::path::Path,
        fd: i32,
        tag: &str,
        event_tx: EventTx,
    ) -> Result<CaptureOutput> {
        let fifo = tmpdir.join(fd.to_string());
        use nix::sys::stat::Mode;
        nix::unistd::mkfifo(
            &fifo,
            Mode::S_IRUSR | Mode::S_IWUSR, //| Mode::S_IROTH | Mode::S_IWOTH,
        )
        .context("Failed to mkfifo")?;

        // Open the writing part in blocking mode
        let write = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .with_context(|| format!("Failed to open fifo {}", fifo.display()))?;

        let read = fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(&fifo)
            .await
            .with_context(|| format!("Failed to open fifo {}", fifo.display()))?;

        let stop_source = stop_token::StopSource::new();
        let lines = io::BufReader::new(read).lines();
        // Wrap lines in stop_source
        let mut lines = stop_source.stop_token().stop_stream(lines);

        let tag = tag.to_string();
        task::spawn(async move {
            // The removal of tmpdir lines return a None and the loop breaks
            while let Some(Ok(line)) = lines.next().await {
                event_tx
                    .send(Event::ChildOutput {
                        name: tag.clone(),
                        fd,
                        line,
                    })
                    .await;
            }
        });

        Ok(CaptureOutput {
            stop_source,
            fd,
            write,
        })
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }

    pub fn write_fd(&self) -> i32 {
        self.write.as_raw_fd()
    }
}

#[derive(Debug)]
pub struct Process {
    /// PID of this process
    pid: u32,
    /// Handle to a libminijail configuration
    jail: minijail::Minijail,
    /// If the process is intentionally shut down the termination_reason
    /// is set. This is used to distinguish crashes and graceful shutdowns
    termination_reason: Option<TerminationReason>,
    /// Timstamp when the process is spawned
    started: time::Instant,
    /// Handle to the main loop.
    event_tx: EventTx,
    /// Internal rx part of the shutdown detection
    exit: Option<sync::Receiver<i32>>,
    /// Temporary directory created in the systems tmp folder.
    /// This directory holds process instance specific data that needs
    /// to be dumped to disk for startup. e.g seccomp config (TODO)
    tmpdir: tempfile::TempDir,
    /// Captured stdout output
    stdout: CaptureOutput,
    /// Captured stderr output
    stderr: CaptureOutput,
}

impl Process {
    pub fn termination_reason(&self) -> Option<TerminationReason> {
        self.termination_reason.clone()
    }

    pub fn start_timestamp(&self) -> time::Instant {
        self.started
    }

    pub async fn spawn(container: &Container, event_tx: EventTx) -> Result<Process> {
        let root: std::path::PathBuf = container.root.clone().into();
        let manifest = &container.manifest;
        let mut jail = minijail::Minijail::new().context("Failed to build a minijail")?;

        let cmd = match &manifest.init {
            Some(a) => a.clone(),
            None => {
                let error = format!(
                    "Cannot start a resource container {}:{}",
                    manifest.name, manifest.version
                );
                warn!("{}", error);
                return Err(anyhow!(error));
            }
        };

        let tmpdir = tempfile::TempDir::new()
            .with_context(|| format!("Failed to create tmpdir for {}", manifest.name))?;
        let tmpdir_path = tmpdir.path();

        jail.log_to_fd(
            1,
            if SETTINGS.debug {
                LogPriority::Trace
            } else {
                LogPriority::Info
            },
        );

        let stdout = CaptureOutput::new(tmpdir_path, 1, &manifest.name, event_tx.clone()).await?;
        jail.preserve_fd(stdout.write_fd(), stdout.fd())
            .context("Failed to map child stdout to stdout fifo")?;

        let stderr = CaptureOutput::new(tmpdir_path, 2, &manifest.name, event_tx.clone()).await?;
        jail.preserve_fd(stderr.write_fd(), stderr.fd())
            .context("Failed to map child stdout to stdout fifo")?;

        // Dump seccomp config to process tmpdir. This is a subject to be changed since
        // minijail provides a API to configure seccomp without writing to a file.
        // TODO: configure seccomp via API instead of a file
        if let Some(ref seccomp) = container.manifest.seccomp {
            let seccomp_config = tmpdir_path.join("seccomp");
            let mut f = fs::File::create(&seccomp_config)
                .await
                .context("Failed to create seccomp configuraiton")?;
            let s = itertools::join(seccomp.iter().map(|(k, v)| format!("{}: {}", k, v)), "\n");
            f.write_all(s.as_bytes())
                .await
                .context("Failed to write seccomp configuraiton")?;

            // Temporary disabled
            // Must be called before parse_seccomp_filters
            // jail.log_seccomp_filter_failures();
            // let p: std::path::PathBuf = seccomp_config.into();
            // jail.parse_seccomp_filters(p.as_path())
            //     .context("Failed parse seccomp config")?;
            // jail.use_seccomp_filter();
        }

        // Configure UID
        jail.change_uid(SYSTEM_UID);
        // Configure PID
        jail.change_gid(SYSTEM_GID);

        // TODO: Do not use pid namespace because of multithreadding
        // issues discovered by minijail. See libminijail.c for details.
        // Make the process enter a pid namespace
        //jail.namespace_pids();

        // Make the process enter a vfs namespace
        jail.namespace_vfs();
        // Set no_new_privs. See </kernel/seccomp.c> and </kernel/sys.c>
        // in the kernel source tree for an explanation of the parameters.
        jail.no_new_privs();
        // Set chroot dir for process
        jail.enter_chroot(&root.as_path())?;
        // Make the application the init process
        jail.run_as_init();

        // Configure bind mounts
        #[cfg(target_os = "android")]
        let mounts = &["/sys", "/dev", "/proc", "/system"];
        #[cfg(target_os = "linux")]
        let mounts = &["/sys", "/dev", "/proc", "/lib", "/lib64"];
        #[cfg(any(target_os = "linux", target_os = "android"))]
        for mount in mounts {
            let path = std::path::PathBuf::from(mount);
            mount_bind(&mut jail, &path.as_path(), &path.as_path(), false)?;
        }

        // /data is mounted rw
        let data: std::path::PathBuf = container.data.clone().into();
        mount_bind(
            &mut jail,
            &data.as_path(),
            &std::path::PathBuf::from("/data").as_path(),
            true,
        )?;

        // Mount resource containers
        for (src_dir, mountpoint) in
            collect_resource_folders(container.manifest.resources.as_ref())?
        {
            info!(
                "Mounting from src_dir {} to target {:?}",
                src_dir.display(),
                mountpoint
            );
            mount_bind(&mut jail, &src_dir, &mountpoint, false)?;
        }
        if let Some(resources) = &container.manifest.resources {
            for res in resources {
                if let Ok(cwd) = std::env::current_dir() {
                    let dir_in_container_path = std::path::Path::new(&res.dir);
                    let first_part_of_path = cwd
                        .join(SETTINGS.directories.run_dir.to_owned())
                        .join(res.name.to_owned());
                    let src_dir = match dir_in_container_path.strip_prefix("/") {
                        Ok(dir_in_resource_container) => {
                            first_part_of_path.join(dir_in_resource_container)
                        }
                        Err(_) => first_part_of_path,
                    };
                    info!("src_dir {:?} exists: {}", src_dir, src_dir.exists());
                    if !src_dir.exists() {}
                    info!(
                        "Mounting from src_dir {} to target {:?}",
                        src_dir.display(),
                        res.mountpoint
                    );
                    mount_bind(&mut jail, src_dir.as_ref(), &res.mountpoint, false)?;
                }
            }
        }

        let args = if let Some(ref args) = manifest.args {
            args.iter().map(|a| a.as_str()).collect()
        } else {
            vec![]
        };

        // Create environment for process. Set data directory, container name and version
        let mut env = manifest.env.clone().unwrap_or_default();
        env.push((ENV_DATA.to_string(), "/data".to_string())); // TODO OSX
        env.push((ENV_NAME.to_string(), manifest.name.to_string()));
        env.push((ENV_VERSION.to_string(), manifest.version.to_string()));
        let env = env
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>();
        let env = env.iter().map(|a| a.as_str()).collect::<Vec<&str>>();

        let started = time::Instant::now();

        let pid = jail.run(
            &std::path::PathBuf::from(cmd.as_path()),
            &[1, 2],
            &args,
            &env,
        )? as u32;

        let (exit_tx, exit_rx) = sync::channel::<i32>(1);

        let process = Process {
            pid,
            jail,
            started,
            event_tx: event_tx.clone(),
            termination_reason: None,
            exit: Some(exit_rx),
            tmpdir,
            stdout,
            stderr,
        };

        // Spawn background task that waits for the process exit
        wait_for_exit(&container.manifest.name, pid, exit_tx, event_tx.clone());

        Ok(process)
    }

    pub async fn terminate(
        &mut self,
        time_to_kill: Duration,
        termination_reason: Option<TerminationReason>,
    ) -> Result<impl Future<Output = ExitStatus>> {
        let pid = self.pid;

        // Send a SIGTERM to the application. If the application does not terminate with a timeout
        // it is SIGKILLed.
        signal::kill(Pid::from_raw(pid as i32), Some(Signal::SIGTERM))
            .with_context(|| format!("Failed to SIGTERM {}", self.pid))?;

        let tx = self.event_tx.clone();

        self.termination_reason = termination_reason;

        let mut exit_rx = if let Some(exit_rx) = self.exit.take() {
            exit_rx
        } else {
            warn!("Called terminate on already exiting process {}", pid);
            return Err(anyhow!(
                "Terminate called on already exiting process {}",
                pid
            ));
        };

        // Spawn a task that kills the process if it doesn't exit within time_to_kill
        Ok(task::spawn(async move {
            let mut timeout = Box::pin(task::sleep(time_to_kill).fuse());
            let mut exited = Box::pin(exit_rx.next().fuse());

            select! {
                _ = exited => {
                    ExitStatus::Exit(0)
                }, // This is the happy path...
                _ = timeout => {
                    if let Err(e) = signal::kill(Pid::from_raw(pid as i32), Some(Signal::SIGKILL)) {
                        // If we couldn't send a SIGKILL we have a problem
                        tx.send(Event::Error(anyhow!("Failed to kill pid {}", pid)))
                            .await;
                    }
                    ExitStatus::Killed
                }
            }
        }))
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }
}

/// Spawn a task that waits for the process to exit. Once the process is exited send the return code
// (if any) to the exit_tx handle passed
fn wait_for_exit(name: &str, pid: u32, exit_tx: sync::Sender<i32>, event_tx: EventTx) {
    let name = name.to_string();
    task::spawn(async move {
        let exit_code: i32 = task::spawn_blocking(move || {
            let pid = Pid::from_raw(pid as i32);
            let result = wait::waitpid(Some(pid), None);
            debug!("Result of wait_pid is {:?}", result);

            match result {
                // The process exited normally (as with exit() or returning from main) with the given exit code.
                // This case matches the C macro WIFEXITED(status); the second field is WEXITSTATUS(status).
                Ok(WaitStatus::Exited(_pid, code)) => code,

                // The process was killed by the given signal.
                // The third field indicates whether the signal generated a core dump. This case matches the C macro WIFSIGNALED(status); the last two fields correspond to WTERMSIG(status) and WCOREDUMP(status).
                Ok(WaitStatus::Signaled(_pid, signal, _dump)) => match signal {
                    Signal::SIGTERM => 0,
                    _ => 1,
                },

                // The process is alive, but was stopped by the given signal.
                //  This is only reported if WaitPidFlag::WUNTRACED was passed. This case matches the C macro WIFSTOPPED(status); the second field is WSTOPSIG(status).
                Ok(WaitStatus::Stopped(_pid, _signal)) => 1,

                // The traced process was stopped by a PTRACE_EVENT_* event.
                // See nix::sys::ptrace and ptrace(2) for more information. All currently-defined events use SIGTRAP as the signal; the third field is the PTRACE_EVENT_* value of the event.
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Ok(WaitStatus::PtraceEvent(_pid, _signal, _)) => 1,

                // The traced process was stopped by execution of a system call, and PTRACE_O_TRACESYSGOOD is in effect.
                // See ptrace(2) for more information.
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Ok(WaitStatus::PtraceSyscall(_pid)) => 1,

                // The process was previously stopped but has resumed execution after receiving a SIGCONT signal.
                // This is only reported if WaitPidFlag::WCONTINUED was passed. This case matches the C macro WIFCONTINUED(status).
                Ok(WaitStatus::Continued(_pid)) => 1,

                // There are currently no state changes to report in any awaited child process.
                // This is only returned if WaitPidFlag::WNOHANG was used (otherwise wait() or waitpid() would block until there was something to report).
                Ok(WaitStatus::StillAlive) => unreachable!(),
                Err(e) => {
                    warn!("Failed to waitpid on {}: {}", pid, e);
                    1
                }
            }
        })
        .await;

        exit_tx.send(exit_code).await;
        event_tx
            .send(Event::Exit(name.to_string(), exit_code))
            .await;
    });
}

fn shared_resource(res: &Resource) -> Result<std::path::PathBuf> {
    let cwd = std::env::current_dir()?;
    let dir_in_container_path = std::path::Path::new(&res.dir);
    let first_part_of_path = cwd
        .join(SETTINGS.directories.run_dir.to_owned())
        .join(res.name.to_owned());
    let src_dir = match dir_in_container_path.strip_prefix("/") {
        Ok(dir_in_resource_container) => first_part_of_path.join(dir_in_resource_container),
        Err(_) => first_part_of_path,
    };
    if src_dir.exists() {
        Ok(src_dir)
    } else {
        let error = format!("Resource folder missing: {}", src_dir.display());
        warn!("{}", error);
        Err(anyhow!(error))
    }
}

fn collect_resource_folders(
    needed_resources: Option<&Vec<Resource>>,
) -> Result<Vec<(std::path::PathBuf, std::path::PathBuf)>> {
    let mut resources_to_mount = vec![];
    if let Some(resources) = &needed_resources {
        for res in *resources {
            resources_to_mount.push((shared_resource(res)?, res.mountpoint.clone()));
        }
    }
    Ok(resources_to_mount)
}

fn mount_bind(
    jail: &mut minijail::Minijail,
    src: &std::path::Path,
    dest: &std::path::Path,
    writable: bool,
) -> Result<()> {
    jail.mount_bind(&src, &dest, writable).with_context(|| {
        format!(
            "Failed to add bind mount of {} to {}",
            src.display(),
            dest.display(),
        )
    })
}
