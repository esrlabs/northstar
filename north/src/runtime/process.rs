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

use super::{npk::Container, Event, EventTx};
use anyhow::{anyhow, Result};
use async_std::{sync, task};
use async_trait::async_trait;
use futures::{select, FutureExt, StreamExt};
use log::debug;
use nix::{
    sys::{signal, wait},
    unistd,
};
use std::{fmt::Debug, time};
use wait::WaitStatus;

const ENV_NAME: &str = "NAME";
const ENV_VERSION: &str = "VERSION";

type ExitCode = i32;
pub type Pid = u32;

#[derive(Clone, Debug)]
pub enum ExitStatus {
    /// Process exited with exit code
    Exit(ExitCode),
    /// Process was killed
    Killed,
}

#[derive(Debug)]
struct ExitHandleWait(sync::Receiver<ExitStatus>);

#[derive(Clone, Debug)]
struct ExitHandleSignal(sync::Sender<ExitStatus>);

impl ExitHandleSignal {
    pub async fn signal(&mut self, status: ExitStatus) {
        self.0.send(status).await
    }
}

#[derive(Debug)]
pub struct ExitHandle {
    signal: ExitHandleSignal,
    wait: ExitHandleWait,
}

impl ExitHandle {
    pub fn new() -> ExitHandle {
        let (tx, rx) = sync::channel(1);
        ExitHandle {
            signal: ExitHandleSignal(tx),
            wait: ExitHandleWait(rx),
        }
    }
    async fn wait(&mut self) -> Option<ExitStatus> {
        self.wait.0.next().await
    }

    fn signal(&self) -> ExitHandleSignal {
        self.signal.clone()
    }
}

#[async_trait]
pub trait Process: Debug + Sync + Send {
    fn pid(&self) -> Pid;
    async fn stop(&mut self, timeout: time::Duration) -> Result<ExitStatus>;
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub mod os {
    use super::*;
    use anyhow::Context;
    use std::process;

    #[derive(Debug)]
    pub struct OsProcess {
        exit_handle: ExitHandle,
        child: process::Child,
    }

    impl OsProcess {
        pub async fn start(container: &Container, event_tx: EventTx) -> Result<OsProcess> {
            let manifest = &container.manifest;

            // Init
            let init = if let Some(ref init) = manifest.init {
                init.display().to_string()
            } else {
                return Err(anyhow!(
                    "Cannot start a resource container {}:{}",
                    manifest.name,
                    manifest.version
                ));
            };
            let init = container.root.join(init.trim_start_matches('/'));

            // Command
            let mut cmd = std::process::Command::new(&init);

            // Arguments
            manifest.args.as_ref().map(|args| cmd.args(args));

            // Environment
            let mut env = manifest.env.clone().unwrap_or_default();
            env.insert(ENV_NAME.to_string(), manifest.name.to_string());
            env.insert(ENV_VERSION.to_string(), manifest.version.to_string());
            cmd.envs(env.drain());

            // Spawn
            let child = cmd
                .spawn()
                .with_context(|| format!("Failed to execute {}", init.display()))?;

            let pid = child.id();
            debug!("Started {}", container.manifest.name);

            let exit_handle = ExitHandle::new();
            // Spawn a task thats waits for the child to exit
            waitpid(&manifest.name, pid, exit_handle.signal(), event_tx).await;

            Ok(OsProcess { exit_handle, child })
        }
    }

    #[async_trait]
    impl Process for OsProcess {
        fn pid(&self) -> Pid {
            self.child.id()
        }

        async fn stop(&mut self, timeout: time::Duration) -> Result<ExitStatus> {
            // Send a SIGTERM to the application. If the application does not terminate with a timeout
            // it is SIGKILLed.
            let sigterm = signal::Signal::SIGTERM;
            signal::kill(unistd::Pid::from_raw(self.child.id() as i32), Some(sigterm))
                .with_context(|| format!("Failed to SIGTERM {}", self.child.id()))?;

            let mut timeout = Box::pin(task::sleep(timeout).fuse());
            let mut exited = Box::pin(self.exit_handle.wait()).fuse();

            let pid = self.child.id();
            Ok(select! {
                s = exited => {
                    if let Some(exit_status) = s {
                        exit_status
                    } else {
                        return Err(anyhow!("Internal error"));
                    }
                }, // This is the happy path...
                _ = timeout => {
                    signal::kill(unistd::Pid::from_raw(pid as i32), Some(signal::Signal::SIGKILL))?;
                    ExitStatus::Killed
                }
            })
        }
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod minijail {
    use super::*;
    use crate::{
        manifest::{MountFlag, MountType},
        runtime::{Event, EventTx},
    };
    use anyhow::{Context, Result};
    use async_std::{
        fs, io,
        path::{Path, PathBuf},
        task,
    };
    use futures::StreamExt;
    use io::prelude::{BufReadExt, WriteExt};
    use log::warn;
    use nix::unistd::{self, chown};
    use std::{fmt, os::unix::io::AsRawFd};
    use stop_token::StopSource;

    // We need a Send + Sync version of Minijail
    struct Minijail(::minijail::Minijail);
    unsafe impl Send for Minijail {}
    unsafe impl Sync for Minijail {}

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

        pub fn read_fd(&self) -> i32 {
            self.fd
        }

        pub fn write_fd(&self) -> i32 {
            self.write.as_raw_fd()
        }
    }

    pub struct MinijailProcess {
        /// PID of this process
        pid: u32,
        /// Handle to a libminijail configuration
        _jail: Minijail,
        /// Temporary directory created in the systems tmp folder.
        /// This directory holds process instance specific data that needs
        /// to be dumped to disk for startup. e.g seccomp config (TODO)
        _tmpdir: tempfile::TempDir,
        /// Captured stdout output
        _stdout: CaptureOutput,
        /// Captured stderr output
        _stderr: CaptureOutput,
        /// Sender and receiver for signaling this process exit
        exit_handle: ExitHandle,
    }

    impl fmt::Debug for MinijailProcess {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Process").field("pid", &self.pid).finish()
        }
    }

    impl MinijailProcess {
        pub async fn start(
            container: &Container,
            event_tx: EventTx,
            run_dir: &Path,
            data_dir: &Path,
            uid: u32,
            gid: u32,
        ) -> Result<MinijailProcess> {
            let root: std::path::PathBuf = container.root.clone().into();
            let manifest = &container.manifest;
            let mut jail = ::minijail::Minijail::new().context("Failed to build a minijail")?;

            let init = manifest
                .init
                .as_ref()
                .ok_or_else(|| anyhow!("Cannot start a resource"))?;

            let tmpdir = tempfile::TempDir::new()
                .with_context(|| format!("Failed to create tmpdir for {}", manifest.name))?;
            let tmpdir_path = tmpdir.path();

            let stdout =
                CaptureOutput::new(tmpdir_path, 1, &manifest.name, event_tx.clone()).await?;
            let stderr =
                CaptureOutput::new(tmpdir_path, 2, &manifest.name, event_tx.clone()).await?;

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
            jail.change_uid(uid);
            // Configure PID
            jail.change_gid(gid);

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

            // Create a minimal dev folder in a tmpfs and mount on /dev
            jail.mount_dev();
            // Mount a tmpfs on /tmp
            jail.mount_tmp();
            // Mount /proc
            mount_bind(&mut jail, Path::new("/proc"), Path::new("/proc"), false)?;

            if let Some(ref mounts) = container.manifest.mounts {
                for mount in mounts {
                    match mount.r#type {
                        // Bind mounts
                        MountType::Bind => {
                            if let Some(ref source) = mount.source {
                                // Check if the source exists. If not issue a warning
                                if source.exists() {
                                    let source: PathBuf = source.clone().into();
                                    let target: PathBuf = mount.target.clone().into();
                                    debug!(
                                        "Bind mounting {} to {}",
                                        source.display(),
                                        target.display()
                                    );
                                    mount_bind(&mut jail, &source, &target, false)?;
                                } else {
                                    warn!(
                                        "Cannot bind mount nonexitent source {} to {}",
                                        source.display(),
                                        mount.target.display()
                                    );
                                }
                            } else {
                                // TODO: Bind mounts without a source are invalid and should be checked in Manifest::verify
                                return Err(anyhow!("Cannot mount of type bind without source"));
                            }
                        }
                        MountType::Data => {
                            let dir = data_dir.join(&container.manifest.name);
                            debug!("Creating {}", dir.display());
                            fs::create_dir_all(&dir)
                                .await
                                .with_context(|| format!("Failed to create {}", dir.display()))?;
                            let d: &std::path::Path = dir.as_path().into();
                            debug!("Chowning {} to {}:{}", d.display(), uid, gid);
                            chown(
                                d,
                                Some(unistd::Uid::from_raw(uid)),
                                Some(unistd::Gid::from_raw(gid)),
                            )
                            .with_context(|| {
                                format!("Failed to chown {} to {}:{}", d.display(), uid, gid,)
                            })?;
                            let rw = mount
                                .flags
                                .as_ref()
                                .map(|flags| flags.contains(&MountFlag::Rw))
                                .unwrap_or_default();
                            let target: &Path = mount.target.as_path().into();
                            mount_bind(&mut jail, &dir, target, rw)?;
                        }
                    }
                }
            }

            // Instruct minijail to remount /proc ro after entering the mount ns
            // with MS_NODEV | MS_NOEXEC | MS_NOSUID
            jail.remount_proc_readonly();

            // Mount resource containers
            if let Some(ref resources) = container.manifest.resources {
                for res in resources {
                    let shared_resource_path = {
                        let dir_in_container_path: PathBuf = res.dir.clone().into();
                        let first_part_of_path =
                            run_dir.join(&res.name).join(&res.version.to_string());

                        let src_dir = dir_in_container_path
                            .strip_prefix("/")
                            .map(|dir_in_resource_container| {
                                first_part_of_path.join(dir_in_resource_container)
                            })
                            .unwrap_or(first_part_of_path);

                        if src_dir.exists().await {
                            Ok(src_dir)
                        } else {
                            Err(anyhow!(format!(
                                "Resource folder {} is missing",
                                src_dir.display()
                            )))
                        }
                    }?;

                    let target: PathBuf = res.mountpoint.clone().into();
                    mount_bind(&mut jail, &shared_resource_path, target.as_path(), false)?;
                }
            }

            let mut args: Vec<&str> = Vec::new();
            if let Some(init) = &manifest.init {
                if let Some(init_path_str) = init.to_str() {
                    args.push(init_path_str);
                }
            };
            if let Some(ref manifest_args) = manifest.args {
                for a in manifest_args {
                    args.push(a);
                }
            }

            // Create environment for process. Set data directory, container name and version
            let mut env = manifest.env.clone().unwrap_or_default();
            env.insert(ENV_NAME.to_string(), manifest.name.to_string());
            env.insert(ENV_VERSION.to_string(), manifest.version.to_string());
            let env = env
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<String>>();
            let env = env.iter().map(|a| a.as_str()).collect::<Vec<&str>>();

            let pid = jail.run_remap_env_preload(
                &std::path::PathBuf::from(init.as_path()),
                &[
                    (stderr.write_fd(), stderr.read_fd()),
                    (stdout.write_fd(), stdout.read_fd()),
                ],
                &args,
                &env,
                false,
            )? as u32;

            let exit_handle = ExitHandle::new();
            // Spawn a task thats waits for the child to exit
            waitpid(&manifest.name, pid, exit_handle.signal(), event_tx).await;

            Ok(MinijailProcess {
                pid,
                _jail: Minijail(jail),
                _tmpdir: tmpdir,
                _stdout: stdout,
                _stderr: stderr,
                exit_handle,
            })
        }
    }

    fn mount_bind(
        jail: &mut ::minijail::Minijail,
        src: &Path,
        target: &Path,
        writable: bool,
    ) -> Result<()> {
        let src: &std::path::Path = src.into();
        let target: &std::path::Path = target.into();
        jail.mount_bind(&src, &target, writable).with_context(|| {
            format!(
                "Failed to add bind mount of {} to {}",
                src.display(),
                target.display(),
            )
        })
    }

    #[async_trait]
    impl Process for MinijailProcess {
        fn pid(&self) -> Pid {
            self.pid
        }

        async fn stop(&mut self, timeout: time::Duration) -> Result<ExitStatus> {
            // Send a SIGTERM to the application. If the application does not terminate with a timeout
            // it is SIGKILLed.
            let sigterm = signal::Signal::SIGTERM;
            signal::kill(unistd::Pid::from_raw(self.pid as i32), Some(sigterm))
                .with_context(|| format!("Failed to SIGTERM {}", self.pid))?;

            let mut timeout = Box::pin(task::sleep(timeout).fuse());
            let mut exited = Box::pin(self.exit_handle.wait()).fuse();

            let pid = self.pid;
            Ok(select! {
                s = exited => {
                    if let Some(exit_status) = s {
                        exit_status
                    } else {
                        return Err(anyhow!("Internal error"));
                    }
                }, // This is the happy path...
                _ = timeout => {
                    signal::kill(unistd::Pid::from_raw(pid as i32), Some(signal::Signal::SIGKILL))?;
                    ExitStatus::Killed
                }
            })
        }
    }
}

/// Spawn a task that waits for the process to exit. Once the process is exited send the return code
// (if any) to the exit_tx handle passed
async fn waitpid(name: &str, pid: u32, mut exit_handle: ExitHandleSignal, event_handle: EventTx) {
    let name = name.to_string();
    task::spawn(async move {
        let exit_code: i32 = task::spawn_blocking(move || {
            let pid = unistd::Pid::from_raw(pid as i32);
            loop {
                let result = wait::waitpid(Some(pid), None);
                debug!("Result of wait_pid is {:?}", result);

                match result {
                    // The process exited normally (as with exit() or returning from main) with the given exit code.
                    // This case matches the C macro WIFEXITED(status); the second field is WEXITSTATUS(status).
                    Ok(WaitStatus::Exited(_pid, code)) => return code,

                    // The process was killed by the given signal.
                    // The third field indicates whether the signal generated a core dump. This case matches the C macro WIFSIGNALED(status); the last two fields correspond to WTERMSIG(status) and WCOREDUMP(status).
                    Ok(WaitStatus::Signaled(_pid, signal, _dump)) => {
                        return match signal {
                            signal::Signal::SIGTERM => 0,
                            _ => 1,
                        }
                    }

                    // The process is alive, but was stopped by the given signal.
                    // This is only reported if WaitPidFlag::WUNTRACED was passed. This case matches the C macro WIFSTOPPED(status); the second field is WSTOPSIG(status).
                    Ok(WaitStatus::Stopped(_pid, _signal)) => continue,

                    // The traced process was stopped by a PTRACE_EVENT_* event.
                    // See nix::sys::ptrace and ptrace(2) for more information. All currently-defined events use SIGTRAP as the signal; the third field is the PTRACE_EVENT_* value of the event.
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    Ok(WaitStatus::PtraceEvent(_pid, _signal, _)) => continue,

                    // The traced process was stopped by execution of a system call, and PTRACE_O_TRACESYSGOOD is in effect.
                    // See ptrace(2) for more information.
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    Ok(WaitStatus::PtraceSyscall(_pid)) => continue,

                    // The process was previously stopped but has resumed execution after receiving a SIGCONT signal.
                    // This is only reported if WaitPidFlag::WCONTINUED was passed. This case matches the C macro WIFCONTINUED(status).
                    Ok(WaitStatus::Continued(_pid)) => continue,

                    // There are currently no state changes to report in any awaited child process.
                    // This is only returned if WaitPidFlag::WNOHANG was used (otherwise wait() or waitpid() would block until there was something to report).
                    Ok(WaitStatus::StillAlive) => continue,
                    // Retry the waitpid call if waitpid fails with EINTR
                    Err(e) if e == nix::Error::Sys(nix::errno::Errno::EINTR) => continue,
                    Err(e) => panic!("Failed to waitpid on {}: {}", pid, e),
                }
            }
        })
        .await;

        let status = ExitStatus::Exit(exit_code);

        exit_handle.signal(status.clone()).await;
        event_handle
            .send(Event::Exit(name.to_string(), status))
            .await;
    });
}
