// Copyright (c) 2020 ESRLabs
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

use super::{exit_handle, waitpid, Error, ExitHandleWait, ExitStatus, Pid, ENV_NAME, ENV_VERSION};
use crate::{
    manifest::{Mount, MountFlag},
    runtime::{npk::Container, Event, EventTx},
};
use log::{debug, warn};
use nix::{
    sys::{signal, stat::Mode},
    unistd::{self, chown},
};
use std::{fmt, ops, os::unix::io::AsRawFd, path::Path};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncWriteExt},
    select,
    stream::StreamExt,
    task, time,
};

// We need a Send + Sync version of Minijail
struct Minijail(::minijail::Minijail);
unsafe impl Send for Minijail {}
unsafe impl Sync for Minijail {}

impl ops::Deref for Minijail {
    type Target = ::minijail::Minijail;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ops::DerefMut for Minijail {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// Capture output of a child process. Create a fifo and spawn a task that forwards each line to
// the main loop. When this struct is dropped the internal spawned tasks are stopped.
#[derive(Debug)]
struct CaptureOutput {
    // Fd
    fd: i32,
    // File instance to the write part. The raw fd of File is passed to minijail
    // and File must be kept in scope to avoid that it is closed.
    write: std::fs::File,
}

impl CaptureOutput {
    pub async fn new(
        tmpdir: &Path,
        fd: i32,
        tag: &str,
        event_tx: EventTx,
    ) -> Result<CaptureOutput, Error> {
        let fifo = tmpdir.join(fd.to_string());
        unistd::mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).map_err(|e| Error::Os {
            context: "Failed to mkfifo".to_string(),
            error: e,
        })?;

        // Open the writing part in blocking mode
        let write = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .map_err(|e| Error::Io {
                context: format!("Failed to open fifo {}", fifo.display()),
                error: e,
            })?;

        let read = fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(&fifo)
            .await
            .map_err(|e| Error::Io {
                context: format!("Failed to open fifo {}", fifo.display()),
                error: e,
            })?;

        let mut lines = io::BufReader::new(read).lines();

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
                    .await
                    .ok();
            }
            debug!("Stopping process capture of {} on fd {}", tag, fd);
        });

        Ok(CaptureOutput { fd, write })
    }

    pub fn read_fd(&self) -> i32 {
        self.fd
    }

    pub fn write_fd(&self) -> i32 {
        self.write.as_raw_fd()
    }
}

pub struct Process {
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
    /// Rx part of the exit handle of this process
    exit_handle_wait: ExitHandleWait,
}

impl fmt::Debug for Process {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Process").field("pid", &self.pid).finish()
    }
}

impl Process {
    pub async fn start(
        container: &Container,
        event_tx: EventTx,
        run_dir: &Path,
        data_dir: &Path,
        uid: u32,
        gid: u32,
    ) -> Result<Process, Error> {
        let root = &container.root;
        let manifest = &container.manifest;
        let mut jail = Minijail(::minijail::Minijail::new().map_err(Error::Minijail)?);

        let init = manifest
            .init
            .as_ref()
            .ok_or_else(|| Error::Start("Cannot start a resource".to_string()))?;

        let tmpdir = tempfile::TempDir::new().map_err(|e| Error::Io {
            context: format!("Failed to create tmpdir for {}", manifest.name),
            error: e,
        })?;
        let tmpdir_path = tmpdir.path();

        let stdout = CaptureOutput::new(tmpdir_path, 1, &manifest.name, event_tx.clone()).await?;
        let stderr = CaptureOutput::new(tmpdir_path, 2, &manifest.name, event_tx.clone()).await?;

        // Dump seccomp config to process tmpdir. This is a subject to be changed since
        // minijail provides a API to configure seccomp without writing to a file.
        // TODO: configure seccomp via API instead of a file
        if let Some(ref seccomp) = container.manifest.seccomp {
            let seccomp_config = tmpdir_path.join("seccomp");
            let mut f = fs::File::create(&seccomp_config)
                .await
                .map_err(|e| Error::Io {
                    context: "Failed to create seccomp configuraiton".to_string(),
                    error: e,
                })?;
            let s = itertools::join(seccomp.iter().map(|(k, v)| format!("{}: {}", k, v)), "\n");
            f.write_all(s.as_bytes()).await.map_err(|e| Error::Io {
                context: "Failed to write seccomp configuraiton".to_string(),
                error: e,
            })?;

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

        setup_mounts(&mut jail, container, &data_dir, uid, gid, &run_dir).await?;

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
            &init.as_path(),
            &[
                (stderr.write_fd(), stderr.read_fd()),
                (stdout.write_fd(), stdout.read_fd()),
            ],
            &args,
            &env,
            false,
        )? as u32;

        let (exit_handle_signal, exit_handle_wait) = exit_handle();
        // Spawn a task thats waits for the child to exit
        waitpid(&manifest.name, pid, exit_handle_signal, event_tx).await;

        Ok(Process {
            pid,
            _jail: jail,
            _tmpdir: tmpdir,
            _stdout: stdout,
            _stderr: stderr,
            exit_handle_wait,
        })
    }
}

async fn setup_mounts(
    jail: &mut Minijail,
    container: &Container,
    data_dir: &Path,
    uid: u32,
    gid: u32,
    run_dir: &Path,
) -> Result<(), Error> {
    // Create a minimal dev folder in a tmpfs and mount on /dev
    jail.mount_dev();
    // Mount a tmpfs on /tmp
    jail.mount_tmp();

    // Mount /proc
    mount_bind(jail, Path::new("/proc"), Path::new("/proc"), false)?;
    // Instruct minijail to remount /proc ro after entering the mount ns
    // with MS_NODEV | MS_NOEXEC | MS_NOSUID
    jail.remount_proc_readonly();

    for mount in container.manifest.mounts.iter() {
        match &mount {
            Mount::Bind {
                target,
                host,
                flags,
            } => {
                let source = host.as_path();
                if !source.exists() {
                    warn!(
                        "Cannot bind mount nonexitent source {} to {}",
                        source.display(),
                        target.display()
                    );
                    continue;
                }
                let rw = flags.contains(&MountFlag::Rw);
                mount_bind(jail, &source, &target, rw)?;
            }
            Mount::Persist { target, flags } => {
                let dir = data_dir.join(&container.manifest.name);
                debug!("Creating {}", dir.display());
                fs::create_dir_all(&dir).await.map_err(|e| Error::Io {
                    context: format!("Failed to create {}", dir.display()),
                    error: e,
                })?;

                debug!("Chowning {} to {}:{}", dir.display(), uid, gid);
                chown(
                    dir.as_os_str(),
                    Some(unistd::Uid::from_raw(uid)),
                    Some(unistd::Gid::from_raw(gid)),
                )
                .map_err(|e| Error::Os {
                    context: format!("Failed to chown {} to {}:{}", dir.display(), uid, gid,),
                    error: e,
                })?;

                let rw = flags.contains(&MountFlag::Rw);
                mount_bind(jail, &dir, &target, rw)?;
            }
            Mount::Resource {
                target,
                name,
                version,
                dir,
            } => {
                let shared_resource_path = {
                    let dir_in_container_path = dir.clone();
                    let first_part_of_path = run_dir.join(&name).join(&version.to_string());

                    let src_dir = dir_in_container_path
                        .strip_prefix("/")
                        .map(|dir_in_resource_container| {
                            first_part_of_path.join(dir_in_resource_container)
                        })
                        .unwrap_or(first_part_of_path);

                    if !src_dir.exists() {
                        return Err(Error::Start(format!(
                            "Resource folder {} is missing",
                            src_dir.display()
                        )));
                    }

                    src_dir
                };

                mount_bind(jail, &shared_resource_path, &target.as_path(), false)?;
            }
            Mount::Tmpfs { target, size } => {
                debug!("Mounting tmpfs to {}", target.display());
                let data = format!("size={},mode=1777", size);
                jail.mount_with_data(&Path::new("none"), &target, "tmpfs", 0, &data)
                    .map_err(Error::Minijail)?;
            }
        }
    }
    Ok(())
}

fn mount_bind(
    jail: &mut ::minijail::Minijail,
    source: &Path,
    target: &Path,
    rw: bool,
) -> Result<(), Error> {
    debug!(
        "Bind mounting {} to {}{}",
        source.display(),
        target.display(),
        if rw { " (rw)" } else { "" }
    );
    jail.mount_bind(&source, &target, rw)
        .map_err(Error::Minijail)
}

#[async_trait::async_trait]
impl super::Process for Process {
    fn pid(&self) -> Pid {
        self.pid
    }

    async fn stop(&mut self, timeout: time::Duration) -> Result<ExitStatus, Error> {
        // Send a SIGTERM to the application. If the application does not terminate with a timeout
        // it is SIGKILLed.
        let sigterm = signal::Signal::SIGTERM;
        signal::kill(unistd::Pid::from_raw(self.pid as i32), Some(sigterm)).map_err(|e| {
            Error::Os {
                context: format!("Failed to SIGTERM {}", self.pid),
                error: e,
            }
        })?;

        let timeout = Box::pin(time::sleep(timeout));
        let exited = Box::pin(self.exit_handle_wait.next());

        let pid = self.pid;
        Ok(select! {
            s = exited => {
                s.expect("Internal channel error during process termination")  // This is the happy path...
            },
            _ = timeout => {
                signal::kill(unistd::Pid::from_raw(pid as i32), Some(signal::Signal::SIGKILL))
                    .map_err(|e| Error::Os { context: "Failed to kill process".to_string(), error: e})?;
                ExitStatus::Signaled(signal::Signal::SIGKILL)
            }
        })
    }
}
