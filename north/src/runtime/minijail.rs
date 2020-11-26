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

use super::process::{
    exit_handle, waitpid, Error, ExitHandleWait, ExitStatus, Pid, ENV_NAME, ENV_VERSION,
};
use crate::runtime::{Event, EventTx};
use itertools::Itertools;
use log::{debug, warn};
use nix::{
    sys::{signal, stat::Mode},
    unistd::{self, chown},
};
use npk::{
    archive::Container,
    manifest::{Dev, Mount, MountFlag},
};
use std::{
    fmt, iter, ops,
    path::{Path, PathBuf},
};
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
        unistd::mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR)
            .map_err(|e| Error::Os("Failed to mkfifo".to_string(), e))?;

        // Open the writing part in blocking mode
        let write = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .map_err(|e| Error::Io(format!("Failed to open fifo {}", fifo.display()), e))?;

        let read = fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(&fifo)
            .await
            .map_err(|e| Error::Io(format!("Failed to open fifo {}", fifo.display()), e))?;

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
        use std::os::unix::io::AsRawFd;
        self.write.as_raw_fd()
    }
}

pub(super) struct Process {
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
    pub(crate) async fn start(
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

        let tmpdir = tempfile::TempDir::new()
            .map_err(|e| Error::Io(format!("Failed to create tmpdir for {}", manifest.name), e))?;
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
                .map_err(|e| Error::Io("Failed to create seccomp configuraiton".to_string(), e))?;
            let s = itertools::join(seccomp.iter().map(|(k, v)| format!("{}: {}", k, v)), "\n");
            f.write_all(s.as_bytes())
                .await
                .map_err(|e| Error::Io("Failed to write seccomp configuraiton".to_string(), e))?;

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

        // Arguments
        let args = manifest.args.clone().unwrap_or_default();
        let init_str = init.display().to_string();
        let argv: Vec<&str> = iter::once(init_str.as_str())
            .chain(args.iter().map(|s| s.as_str()))
            .collect();

        // Create environment for process. Set data directory, container name and version
        let mut env = manifest.env.clone().unwrap_or_default();
        env.insert(ENV_NAME.to_string(), manifest.name.to_string());
        env.insert(ENV_VERSION.to_string(), manifest.version.to_string());
        let env = env
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>();
        let env = env.iter().map(|a| a.as_str()).collect::<Vec<&str>>();

        debug!(
            "Executing \"{}{}{}\"",
            init.display(),
            if args.len() > 1 { " " } else { "" },
            argv.iter().skip(1).join(" ")
        );

        let pid = jail.run_remap_env_preload(
            &init.as_path(),
            &[
                (stderr.write_fd(), stderr.read_fd()),
                (stdout.write_fd(), stdout.read_fd()),
            ],
            &argv,
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
    let proc = Path::new("/proc");
    jail.mount_bind(&proc, &proc, false)
        .map_err(Error::Minijail)?;
    jail.remount_proc_readonly();

    // If there's no explicit mount for /dev add a minimal variant
    if !container
        .manifest
        .mounts
        .contains_key(&PathBuf::from("/dev"))
    {
        debug!("Mounting minimal /dev");
        jail.mount_dev();
    }

    for (target, mount) in &container.manifest.mounts {
        match &mount {
            Mount::Bind { host, flags } => {
                if !&host.exists() {
                    warn!(
                        "Cannot bind mount nonexitent source {} to {}",
                        host.display(),
                        target.display()
                    );
                    continue;
                }
                let rw = flags.contains(&MountFlag::Rw);
                debug!(
                    "Mounting {} on {}{}",
                    host.display(),
                    target.display(),
                    if rw { " (rw)" } else { "" }
                );
                jail.mount_bind(&host, &target, rw)
                    .map_err(Error::Minijail)?;
            }
            Mount::Persist => {
                let dir = data_dir.join(&container.manifest.name);
                if !dir.exists() {
                    debug!("Creating {}", dir.display());
                    fs::create_dir_all(&dir)
                        .await
                        .map_err(|e| Error::Io(format!("Failed to create {}", dir.display()), e))?;
                }

                debug!("Chowning {} to {}:{}", dir.display(), uid, gid);
                chown(
                    dir.as_os_str(),
                    Some(unistd::Uid::from_raw(uid)),
                    Some(unistd::Gid::from_raw(gid)),
                )
                .map_err(|e| {
                    Error::Os(
                        format!("Failed to chown {} to {}:{}", dir.display(), uid, gid),
                        e,
                    )
                })?;

                debug!("Mounting {} on {}", dir.display(), target.display(),);
                jail.mount_bind(&dir, &target, true)
                    .map_err(Error::Minijail)?;
            }
            Mount::Resource { name, version, dir } => {
                let src = {
                    // Join the source of the resource container with the mount dir
                    let resource_root = run_dir.join(&name).join(&version.to_string());
                    let dir = dir
                        .strip_prefix("/")
                        .map(|d| resource_root.join(d))
                        .unwrap_or(resource_root);

                    if !dir.exists() {
                        return Err(Error::Start(format!(
                            "Resource folder {} is missing",
                            dir.display()
                        )));
                    }

                    dir
                };

                debug!("Mounting {} on {}", src.display(), target.display());

                jail.mount_bind(&src, &target, false)
                    .map_err(Error::Minijail)?;
            }
            Mount::Tmpfs { size } => {
                debug!(
                    "Mounting tmpfs with size {} on {}",
                    bytesize::ByteSize::b(*size),
                    target.display()
                );
                let data = format!("size={},mode=1777", size);
                jail.mount_with_data(&Path::new("none"), &target, "tmpfs", 0, &data)
                    .map_err(Error::Minijail)?;
            }
            Mount::Dev { r#type } => {
                match r#type {
                    // The Full mount of /dev is a simple rw bind mount of /dev
                    Dev::Full => {
                        let dev = Path::new("/dev");
                        jail.mount_bind(&dev, &dev, true).map_err(Error::Minijail)?;
                    }
                }
            }
        }
    }
    Ok(())
}

#[async_trait::async_trait]
impl super::process::Process for Process {
    fn pid(&self) -> Pid {
        self.pid
    }

    async fn stop(&mut self, timeout: time::Duration) -> Result<ExitStatus, Error> {
        // Send a SIGTERM to the application. If the application does not terminate with a timeout
        // it is SIGKILLed.
        let sigterm = signal::Signal::SIGTERM;
        signal::kill(unistd::Pid::from_raw(self.pid as i32), Some(sigterm))
            .map_err(|e| Error::Os(format!("Failed to SIGTERM {}", self.pid), e))?;

        let timeout = Box::pin(time::sleep(timeout));
        let exited = Box::pin(self.exit_handle_wait.next());

        let pid = self.pid;
        Ok(select! {
            s = exited => {
                s.expect("Internal channel error during process termination")  // This is the happy path...
            },
            _ = timeout => {
                signal::kill(unistd::Pid::from_raw(pid as i32), Some(signal::Signal::SIGKILL))
                    .map_err(|e| Error::Os("Failed to kill process".to_string(), e))?;
                ExitStatus::Signaled(signal::Signal::SIGKILL)
            }
        })
    }
}
