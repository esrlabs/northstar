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

use super::{
    process::{
        exit_handle, waitpid, Error, ExitHandleWait, ExitStatus, Pid, ENV_NAME, ENV_VERSION,
    },
    state::Container,
    OutputStream,
};
use crate::runtime::{Event, EventTx};
use futures::channel::oneshot;
use itertools::Itertools;
use log::{debug, error, info, trace, warn, Level};
use nix::{
    fcntl::{self, fcntl, OFlag},
    sys::signal,
    unistd::{self, chown, pipe},
};
use npk::manifest::{Dev, Mount, MountFlag};
use std::{
    fmt, iter, ops,
    os::unix::prelude::RawFd,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    fs,
    io::{self, unix::AsyncFd, AsyncBufReadExt, AsyncRead, AsyncWriteExt, ReadBuf},
    select, task, time,
};

// We need a Send + Sync version of minijail::Minijail
struct MinijailHandle(::minijail::Minijail);

unsafe impl Send for MinijailHandle {}
unsafe impl Sync for MinijailHandle {}

impl ops::Deref for MinijailHandle {
    type Target = ::minijail::Minijail;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ops::DerefMut for MinijailHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug)]
pub struct Minijail {
    log_fd: i32,
    event_tx: EventTx,
    run_dir: PathBuf,
    data_dir: PathBuf,
}

impl Minijail {
    pub(crate) fn new(
        event_tx: EventTx,
        run_dir: &Path,
        data_dir: &Path,
    ) -> Result<Minijail, Error> {
        let pipe = AsyncPipe::new()?;
        let log_fd = pipe.writefd();
        let mut lines = io::BufReader::new(pipe).lines();

        // Spawn a task that forwards logs from minijail to the rust logger.
        task::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                let l = line.split_whitespace().skip(2).collect::<String>();
                match line.chars().next() {
                    Some('D') => debug!("{}", l),
                    Some('I') => info!("{}", l),
                    Some('W') => warn!("{}", l),
                    Some('E') => error!("{}", l),
                    _ => trace!("{}", line),
                }
            }
        });

        let minijail_log_level = match log::max_level().to_level().unwrap_or(Level::Warn) {
            Level::Error => 3,
            Level::Warn => 4,
            Level::Info => 6,
            Level::Debug => 7,
            Level::Trace => i32::MAX,
        };
        ::minijail::Minijail::log_to_fd(log_fd, minijail_log_level as i32);
        Ok(Minijail {
            event_tx,
            run_dir: run_dir.into(),
            data_dir: data_dir.into(),
            log_fd,
        })
    }

    pub(crate) fn shutdown(&self) -> Result<(), Error> {
        // Just make clippy happy
        if false {
            Err(Error::Stop)
        } else {
            Ok(())
        }
    }

    pub(crate) async fn start(&self, container: &Container) -> Result<Process, Error> {
        let root = &container.root;
        let manifest = &container.manifest;
        let mut jail = MinijailHandle(::minijail::Minijail::new().map_err(Error::Minijail)?);

        let init = manifest
            .init
            .as_ref()
            .ok_or_else(|| Error::Start("Cannot start a resource".to_string()))?;

        let uid = manifest.uid;
        let gid = manifest.gid;

        let tmpdir = tempfile::TempDir::new()
            .map_err(|e| Error::Io(format!("Failed to create tmpdir for {}", manifest.name), e))?;
        let tmpdir_path = tmpdir.path();

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

        debug!("Setting UID to {}", uid);
        jail.change_uid(uid);
        debug!("Setting GID to {}", gid);
        jail.change_gid(gid);

        // Update the capability mask if specified
        if let Some(capabilities) = &manifest.capabilities {
            // TODO: the capabilities should be passed as an array
            jail.update_caps(&capabilities.join(" "))
                .map_err(Error::Minijail)?;
        }

        // Update the supplementary group list if specified
        if let Some(suppl_groups) = &manifest.suppl_groups {
            // TODO: the groups should be passed an array
            jail.update_suppl_groups(&suppl_groups.join(" "))
                .map_err(Error::Minijail)?;
        }

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

        self.setup_mounts(&mut jail, container, uid, gid).await?;

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

        let stdout =
            CaptureOutput::new(OutputStream::Stdout, &manifest.name, self.event_tx.clone()).await?;
        let stderr =
            CaptureOutput::new(OutputStream::Stderr, &manifest.name, self.event_tx.clone()).await?;

        // Prevent minijail to close the log fd so that errors aren't missed
        let log_fd = (self.log_fd, self.log_fd);
        let pid = jail.run_remap_env_preload(
            &init.as_path(),
            &[(stdout.0, 1), (stderr.0, 2), log_fd],
            &argv,
            &env,
            false,
        )? as u32;

        let (exit_handle_signal, exit_handle_wait) = exit_handle();
        // Spawn a task thats waits for the child to exit
        waitpid(
            &manifest.name,
            pid,
            exit_handle_signal,
            self.event_tx.clone(),
        )
        .await;

        Ok(Process {
            pid,
            _jail: jail,
            _tmpdir: tmpdir,
            _stdout: stdout,
            _stderr: stderr,
            exit_handle_wait,
        })
    }

    async fn setup_mounts(
        &self,
        jail: &mut MinijailHandle,
        container: &Container,
        uid: u32,
        gid: u32,
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
                    let dir = self.data_dir.join(&container.manifest.name);
                    if !dir.exists() {
                        debug!("Creating {}", dir.display());
                        fs::create_dir_all(&dir).await.map_err(|e| {
                            Error::Io(format!("Failed to create {}", dir.display()), e)
                        })?;
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
                        let resource_root = self.run_dir.join(&name).join(&version.to_string());
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
}

pub(crate) struct Process {
    /// PID of this process
    pid: u32,
    /// Handle to a libminijail configuration
    _jail: MinijailHandle,
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
    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub async fn stop(&mut self, timeout: time::Duration) -> Result<ExitStatus, Error> {
        // Send a SIGTERM to the application. If the application does not terminate with a timeout
        // it is SIGKILLed.
        let sigterm = signal::Signal::SIGTERM;
        signal::kill(unistd::Pid::from_raw(self.pid as i32), Some(sigterm))
            .map_err(|e| Error::Os(format!("Failed to SIGTERM {}", self.pid), e))?;

        let timeout = Box::pin(time::sleep(timeout));
        let exited = Box::pin(self.exit_handle_wait.recv());

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

struct AsyncPipe {
    inner: AsyncFd<std::fs::File>,
    writefd: i32,
}

impl AsyncPipe {
    fn new() -> Result<AsyncPipe, Error> {
        let (readfd, writefd) =
            pipe().map_err(|e| Error::Os("Failed to create pipe".to_string(), e))?;

        let mut flags = OFlag::from_bits(fcntl(readfd, fcntl::FcntlArg::F_GETFL).unwrap()).unwrap();

        flags.set(OFlag::O_NONBLOCK, true);
        fcntl(readfd, fcntl::FcntlArg::F_SETFL(flags)).expect("Failed to configure pipe fd");

        let pipe =
            unsafe { <std::fs::File as std::os::unix::prelude::FromRawFd>::from_raw_fd(readfd) };
        let inner = AsyncFd::new(pipe).map_err(|e| Error::Io("Async fd".to_string(), e))?;
        Ok(AsyncPipe { inner, writefd })
    }

    fn writefd(&self) -> RawFd {
        self.writefd
    }
}

impl AsyncRead for AsyncPipe {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = futures::ready!(self.inner.poll_read_ready(cx))?;
            match guard
                .try_io(|inner| std::io::Read::read(&mut inner.get_ref(), buf.initialized_mut()))
            {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    break Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => break Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

// Capture output of a child process. Create a pipe and spawn a task that forwards each line to
// the main loop. When this struct is dropped the internal spawned tasks are stopped.
#[derive(Debug)]
struct CaptureOutput(i32, oneshot::Sender<()>);

impl CaptureOutput {
    pub async fn new(
        stream: OutputStream,
        tag: &str,
        event_tx: EventTx,
    ) -> Result<CaptureOutput, Error> {
        let pipe = AsyncPipe::new()?;
        let writefd = pipe.writefd();
        let mut lines = io::BufReader::new(pipe).lines();
        let tag = tag.to_string();
        let (tx, mut rx) = oneshot::channel();

        debug!("Starting stream capture of {} on {:?}", tag, stream);
        task::spawn(async move {
            loop {
                select! {
                    _ = &mut rx => break,
                    line = lines.next_line() => {
                        if let Ok(Some(line)) = line {
                            let event = Event::ChildOutput {
                                    name: tag.clone(),
                                    stream: stream.clone(),
                                    line,
                                };
                            event_tx.send(event).await.ok();
                        } else {
                            break;
                        }
                    }
                }
            }
            debug!("Stopped stream capture of {} on {:?}", tag, stream);
        });

        Ok(CaptureOutput(writefd, tx))
    }
}
