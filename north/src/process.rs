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

use crate::{container::Container, Event, EventTx, TerminationReason};
use anyhow::{anyhow, Context, Result};
use async_std::{fs, path, prelude::*, sync, task};
use futures::{future::FutureExt, select, StreamExt};
use itertools::Itertools;
use log::*;
use nix::{
    sys::{signal, signal::Signal, wait, wait::WaitStatus},
    unistd::Pid,
};
use std::{ffi::OsString, future::Future, time, time::Duration};
use subprocess::Popen;

const ENV_VERSION: &str = "VERSION";
const ENV_DATA: &str = "DATA";

#[derive(Debug)]
pub enum ExitStatus {
    Exit(i32),
    Killed,
}

#[derive(Debug)]
pub struct Process {
    pid: u32,
    termination_reason: Option<TerminationReason>,
    started: time::Instant,
    event_tx: EventTx,
    process: Popen, // This is None if the process is terminated
    exit: Option<sync::Receiver<i32>>,
    tmpdir: tempfile::TempDir,
}

impl Process {
    pub fn termination_reason(&self) -> Option<TerminationReason> {
        self.termination_reason.clone()
    }

    pub fn start_timestamp(&self) -> time::Instant {
        self.started
    }

    pub async fn spawn(container: &Container, event_tx: EventTx) -> Result<Process> {
        let manifest = &container.manifest;
        let name = &manifest.name;
        let version = &manifest.version;
        let tmpdir = tempfile::TempDir::new()
            .with_context(|| format!("Failed to create tmpdir for {}", name))?;

        // Prepare env for process
        let mut env = vec![
            (ENV_VERSION.to_string(), version.to_string()),
            // The container get's a env variable with the location of it's rw data directory
            (ENV_DATA.to_string(), target::data(&container)),
        ];
        if let Some(e) = &manifest.env {
            env.extend(e.iter().cloned());
        }

        // Dump seccom config to process tmpdir
        if let Some(ref seccomp) = container.manifest.seccomp {
            let seccomp_config = tmpdir.path().join("seccomp");
            let mut f = fs::File::create(&seccomp_config)
                .await
                .context("Failed to create seccomp configuraiton")?;
            for (k, v) in seccomp {
                f.write_all(format!("{}: {}\n", k, v).as_bytes())
                    .await
                    .context("Failed to write seccomp configuraiton")?;
            }
        }

        // Spawn process
        let cwd = target::cwd(&container).map(OsString::from);
        let tmpdir_path: path::PathBuf = tmpdir.path().to_path_buf().into();
        let argv = target::argv(&container, &tmpdir_path.as_path()).await?;
        let started = time::Instant::now();
        debug!(
            "Spawning {:?} {:?}",
            env.iter().map(|(k, v)| format!("{}={}", k, v)).join(" "),
            argv.iter().join(" "),
        );
        let config = subprocess::PopenConfig {
            cwd,
            env: Some(
                env.iter()
                    .map(|(k, v)| (OsString::from(k), OsString::from(v)))
                    .collect(),
            ),
            #[cfg(target_os = "android")]
            stdout: subprocess::Redirection::Pipe,
            #[cfg(target_os = "android")]
            stderr: subprocess::Redirection::Merge,
            ..Default::default()
        };

        #[cfg(target_os = "android")]
        let mut process = subprocess::Popen::create(&argv, config)
            .with_context(|| format!("Failed to spawn {:?}", argv))?;
        #[cfg(not(target_os = "android"))]
        let process = subprocess::Popen::create(&argv, config)
            .with_context(|| format!("Failed to spawn {:?}", argv))?;

        let pid = match process.pid() {
            Some(pid) => pid,
            None => {
                let error = format!("Failed to get PID for spawned {}:{}", name, version);
                event_tx.send(Event::Error(anyhow!(error.clone()))).await;
                return Err(anyhow!(error));
            }
        };

        // Setup logwrapper if running on android
        #[cfg(target_os = "android")]
        {
            if let Some(stdout) = process.stdout.take() {
                let buffer = container
                    .manifest
                    .log
                    .as_ref()
                    .and_then(|l| l.buffer.clone())
                    .unwrap_or(north_common::manifest::LogBuffer::Main);
                let tag = container
                    .manifest
                    .log
                    .as_ref()
                    .and_then(|l| l.tag.clone())
                    .unwrap_or_else(|| container.manifest.name.clone());
                target::logwrap(stdout, buffer, pid, &tag).await?;
            }
        }

        let (exit_tx, exit_rx) = sync::channel::<i32>(1);

        let process = Process {
            pid,
            process,
            started,
            event_tx: event_tx.clone(),
            termination_reason: None,
            exit: Some(exit_rx),
            tmpdir,
        };

        // Spawn background task that waits for the process exit
        Self::wait_exit(&container.manifest.name, pid, exit_tx, event_tx.clone());

        Ok(process)
    }

    pub async fn terminate(
        &mut self,
        time_to_kill: Duration,
        termination_reason: Option<TerminationReason>,
    ) -> Result<impl Future<Output = ExitStatus>> {
        self.process
            .terminate()
            .with_context(|| format!("Failed to terminate {}", self.pid))?;

        let tx = self.event_tx.clone();
        let pid = self.pid;

        self.termination_reason = termination_reason;

        let mut exit_rx = if let Some(exit_rx) = self.exit.take() {
            exit_rx
        } else {
            warn!("Called terminate on alreasy exiting process {}", pid);
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
                    if let Err(e) = signal::kill(Pid::from_raw(-(pid as i32)), Some(Signal::SIGKILL)) {
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

    fn wait_exit(name: &str, pid: u32, exit_tx: sync::Sender<i32>, event_tx: EventTx) {
        let name = name.to_string();
        task::spawn(async move {
            let exit_code: i32 = task::spawn_blocking(move || {
                let pid = Pid::from_raw(pid as i32);
                let result = wait::waitpid(Some(pid), None);

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
}

#[cfg(not(target_os = "android"))]
mod target {
    use crate::{container::Container, SETTINGS};
    use anyhow::{Context, Result};
    use async_std::path::{Path, PathBuf};

    pub fn data(container: &Container) -> String {
        if SETTINGS.global_data_dir {
            SETTINGS.data_dir.display().to_string()
        } else {
            container.data.display().to_string()
        }
    }

    pub fn cwd(_: &Container) -> Option<PathBuf> {
        None
    }

    pub async fn argv(container: &Container, _: &Path) -> Result<Vec<String>> {
        let init = container
            .manifest
            .init
            .strip_prefix("/")
            .with_context(|| format!("Malformed init: {:?}", container.manifest.init))?;
        let init = container.root.join(&init).display().to_string();
        Ok(vec![init])
    }
}

#[cfg(target_os = "android")]
mod target {
    use crate::{container::Container, SETTINGS};
    use anyhow::{Context, Result};
    use async_std::{
        path::{Path, PathBuf},
        task,
    };
    use bytes::BufMut;
    use log::warn;
    use north_common::manifest;
    use std::{io, io::BufRead, os::unix::net::UnixDatagram, time};

    const MINIJAIL: &str = "/system/bin/minijailng";

    pub fn data(_: &Container) -> String {
        "/data".into()
    }

    pub fn cwd(container: &Container) -> Option<PathBuf> {
        Some(container.root.clone())
    }

    pub async fn argv(container: &Container, tmpdir: &Path) -> Result<Vec<String>> {
        let mut cmd = if PathBuf::from(MINIJAIL).exists().await {
            #[derive(Default)]
            struct Argv(Vec<String>);
            impl Argv {
                pub fn push<T: ToString>(&mut self, arg: T) {
                    self.0.push(arg.to_string())
                }
                pub fn extend<T>(&mut self, args: T)
                where
                    T: std::iter::IntoIterator,
                    T::Item: ToString,
                {
                    self.0.extend(args.into_iter().map(|e| e.to_string()));
                }
            }

            let mut cmd = Argv::default();

            let name = container.manifest.name.clone();

            cmd.push(MINIJAIL);
            // HACK: have minijail create network namespace and IP
            //       bridge name is hardcoded
            if !SETTINGS.disable_network_namespaces {
                let ns = &uuid::Uuid::new_v4().to_string()[..16];
                cmd.push(format!("-E{},nstbr1", ns));
            }

            // Don't use LD_PRELOAD
            cmd.push("-Tstatic");

            // Enter a pid namespace
            cmd.push("-p");

            // Set the no_new_privilges flag to avoid privilge escalation
            cmd.push("-n");

            // Enter a vfs namespace
            cmd.push("-v");

            // UTS hostname
            cmd.push(format!("--uts={}", name));

            // UID/GID mapping, all procs run as system user
            cmd.extend(&["-u", "1000"]);
            cmd.extend(&["-g", "1000"]);

            // Enable seccomp filter logging
            cmd.push("-L");

            // Add seccomp
            if container.manifest.seccomp.is_some() {
                cmd.push("-n");
                cmd.extend(&[
                    "-S".to_string(),
                    tmpdir.join("seccomp").display().to_string(),
                ]);
            }

            // Bind mounts
            cmd.extend(&["-b", "/system,/system"]);
            cmd.extend(&["-b", "/proc,/proc"]);
            cmd.extend(&["-b", "/dev,/dev"]);

            // Mount data dir rw
            cmd.extend(&["-b", &format!("{},/data,1", container.data.display())]);

            // Chroot
            cmd.push("-C");
            cmd.push(container.root.display());
            cmd.push(container.manifest.init.display());
            cmd.0
        } else {
            warn!("Cannot find {:?}!", MINIJAIL);
            let init = container
                .manifest
                .init
                .strip_prefix("/")
                .with_context(|| format!("Malformed init: {:?}", container.manifest.init))?;
            let init = container.root.join(&init);
            vec![init.display().to_string()]
        };

        if let Some(ref args) = container.manifest.args {
            cmd.extend(args.iter().map(String::to_string));
        }

        Ok(cmd)
    }

    pub async fn logwrap<T: io::Read + Send + 'static>(
        read: T,
        buffer_id: manifest::LogBuffer,
        pid: u32,
        tag: &str,
    ) -> Result<()> {
        let socket = UnixDatagram::unbound().context("Failed to create socket")?;
        let tag = tag.to_string();
        socket
            .connect("/dev/socket/logdw")
            .context("Failed to open logdw socket")?;
        let mut lines = io::BufReader::new(read).lines();
        let tag_len = tag.bytes().len();
        let buffer_id = match buffer_id {
            manifest::LogBuffer::Main => 0,
            manifest::LogBuffer::Custom(n) => n,
        };

        let mut buffer = bytes::BytesMut::with_capacity(1024);

        task::spawn_blocking(move || {
            while let Some(Ok(line)) = lines.next() {
                let message_len = line.bytes().len();
                buffer.reserve(12 + tag_len + message_len);

                let timestamp = time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap();
                buffer.put_u8(buffer_id);
                buffer.put_u16_le(pid as u16);
                buffer.put_u32_le(timestamp.as_secs() as u32);
                buffer.put_u32_le(timestamp.subsec_nanos());
                buffer.put_u8(3); // Debug
                buffer.put(tag.as_bytes());
                buffer.put_u8(0);
                buffer.put(line.as_bytes());
                buffer.put_u8(0);
                if socket.send(&buffer).is_err() {
                    warn!("Logger error on pid {}", pid);
                    break;
                }
                buffer.clear();
            }
        });

        Ok(())
    }
}
