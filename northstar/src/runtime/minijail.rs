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
    config::Config,
    error::Error,
    pipe::{pipe, AsyncPipeRead, AsyncPipeWrite, PipeWrite},
    process_debug, Container, Event, ExitStatus, Launcher, MountedContainer, Pid, Process,
};
use crate::runtime::EventTx;
use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use futures::{future::OptionFuture, Future, TryFutureExt};
use itertools::Itertools;
use log::{debug, error, info, trace, warn, Level};
use nix::{
    sys::{signal, wait},
    unistd::{self, chown},
};
use npk::manifest::{Dev, Manifest, Mount, MountFlag, Output};
use signal::Signal::{SIGKILL, SIGTERM};
use std::{
    convert::TryInto,
    fmt, iter, ops,
    os::unix::{io::AsRawFd, prelude::*},
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
    unimplemented,
};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    select,
    task::{self, JoinHandle},
    time,
};
use tokio_util::sync::CancellationToken;
use wait::WaitStatus;

const ENV_NAME: &str = "NAME";
const ENV_VERSION: &str = "VERSION";

#[derive(Debug)]
pub struct Minijail {
    log_fd: PipeWrite,
    event_tx: EventTx,
    config: Config,
    log_task: JoinHandle<()>,
    stop_token: CancellationToken,
}

fn into_io_error(e: ::minijail::Error) -> Error {
    Error::io("minijail", io::Error::new(io::ErrorKind::Other, e))
}

#[async_trait]
impl Launcher for Minijail {
    type Process = MinijailProcess;

    async fn start(event_tx: EventTx, config: Config) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let (reader, log_fd) =
            pipe().map_err(|e| Error::Io("Failed to open pipe".to_string(), e))?;
        let async_reader: AsyncPipeRead = reader.try_into().map_err(|e| {
            Error::Io(
                "Failed to get async handler from pipe reader".to_string(),
                e,
            )
        })?;
        let mut lines = io::BufReader::new(async_reader).lines();

        let stop_token = CancellationToken::new();
        let log_task = {
            let stop_token = stop_token.clone();

            // Spawn a task that forwards logs from minijail to the rust logger.
            task::spawn(async move {
                loop {
                    select! {
                        Ok(Some(line)) = lines.next_line() => {
                            let l = line.split_whitespace().skip(2).collect::<String>();
                            match line.chars().next() {
                                Some('D') => debug!("{}", l),
                                Some('I') => info!("{}", l),
                                Some('W') => warn!("{}", l),
                                Some('E') => error!("{}", l),
                                _ => trace!("{}", line),
                            }
                        }
                        _ = stop_token.cancelled() => break,
                        else => break,
                    }
                }
            })
        };

        let minijail_log_level = match log::max_level().to_level().unwrap_or(Level::Warn) {
            Level::Error => 3,
            Level::Warn => 4,
            Level::Info => 6,
            Level::Debug => 7,
            Level::Trace => i32::MAX,
        };

        ::minijail::Minijail::log_to_fd(log_fd.as_raw_fd(), minijail_log_level as i32);

        Ok(Minijail {
            log_fd,
            event_tx,
            config,
            log_task,
            stop_token,
        })
    }

    async fn shutdown(&mut self) -> Result<(), Error>
    where
        Self: Sized,
    {
        // Set minijail logging to stderr before closing the pipe
        ::minijail::Minijail::log_to_fd(2, i32::MAX);

        // Stop the task that receives the log from minijail
        self.stop_token.cancel();

        Ok(())
    }

    async fn create(
        &self,
        container: &MountedContainer<Self::Process>,
    ) -> Result<Self::Process, Error> {
        let root = &container.root;
        let manifest = &container.manifest;
        let mut jail =
            MinijailHandle(::minijail::Minijail::new().expect("Failed to create minijail handle"));

        let init = manifest.init.as_ref().expect("Cannot start a resource");

        let uid = manifest.uid;
        let gid = manifest.gid;

        // let tmpdir = tempfile::TempDir::new()
        //     .map_err(|e| Error::Io(format!("Failed to create tmpdir for {}", manifest.name), e))?;
        // let tmpdir_path = tmpdir.path();

        // Dump seccomp config to process tmpdir. This is a subject to be changed since
        // minijail provides a API to configure seccomp without writing to a file.
        // TODO: configure seccomp via API instead of a file
        // if let Some(ref seccomp) = container.manifest.seccomp {
        //     let seccomp_config = tmpdir_path.join("seccomp");
        //     let mut f = fs::File::create(&seccomp_config)
        //         .await
        //         .map_err(|e| Error::Io("Failed to create seccomp configuraiton".to_string(), e))?;
        //     let s = itertools::join(seccomp.iter().map(|(k, v)| format!("{}: {}", k, v)), "\n");
        //     f.write_all(s.as_bytes())
        //         .await
        //         .map_err(|e| Error::Io("Failed to write seccomp configuraiton".to_string(), e))?;

        //     // Temporary disabled
        //     // Must be called before parse_seccomp_filters
        //     // jail.log_seccomp_filter_failures();
        //     // let p: std::path::PathBuf = seccomp_config.into();
        //     // jail.parse_seccomp_filters(p.as_path())
        //     //     .context("Failed parse seccomp config")?;
        //     // jail.use_seccomp_filter();
        // }

        debug!("Setting UID to {}", uid);
        jail.change_uid(uid);
        debug!("Setting GID to {}", gid);
        jail.change_gid(gid);

        // Update the capability mask if specified
        if let Some(capabilities) = &manifest.capabilities {
            // TODO: the capabilities should be passed as an array
            jail.update_caps(&capabilities.join(" "))
                .map_err(into_io_error)?;
        }

        // Update the supplementary group list if specified
        if let Some(suppl_groups) = &manifest.suppl_groups {
            // TODO: the groups should be passed an array
            jail.update_suppl_groups(&suppl_groups.join(" "))
                .map_err(into_io_error)?;
        }

        // Make the process enter a pid namespace
        jail.namespace_pids();

        // Make the process enter a vfs namespace
        jail.namespace_vfs();
        // Set no_new_privs. See </kernel/seccomp.c> and </kernel/sys.c>
        // in the kernel source tree for an explanation of the parameters.
        jail.no_new_privs();
        // Set chroot dir for process
        jail.enter_chroot(&root.as_path()).map_err(into_io_error)?;

        Self::setup_mounts(&self.config, &mut jail, container, uid, gid).await?;

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

        // Construct the io objects configured in the manifest toghether with the log_fd
        // that needs to be preserved.
        let (io, mut fds) = self.inheritable_fds(&manifest).await?;

        // Create a child sync
        let sync = ProcessSync::with(&mut jail)?;
        // Add the sync fd to the list of preserved fds
        fds.push((sync.resume_fd(), sync.resume_fd()));
        fds.push((sync.ack_fd(), sync.ack_fd()));

        // And finally start it....
        let argv_str = argv.iter().join(" ");
        debug!("Preparing \"{}\"", argv_str);
        let pid = jail
            .run_remap_env_preload(&init.as_path(), &fds, &argv, &env, false)
            .map_err(into_io_error)?;
        let pid = pid as u32;

        // Attach debug tools if configured in the runtime configuration.
        let debug = Debug::from(&self.config, &manifest, pid).await?;

        // Spawn a task thats waits for the child to exit
        let exit_status = {
            let container = container.container.clone();
            let tx = self.event_tx.clone();
            Box::new(Self::waitpid(container, pid, tx).await)
        };

        Ok(MinijailProcess {
            argv: argv_str,
            pid,
            _jail: jail,
            _io: io,
            exit_status,
            debug,
            sync: Some(sync),
        })
    }
}

impl Minijail {
    /// Configure stdout/stderr as declared in the manifest and return list of fds that
    /// shall be preserved by minijail for the spanwed process
    async fn inheritable_fds(
        &self,
        manifest: &Manifest,
    ) -> Result<((Option<Io>, Option<Io>), Vec<(i32, i32)>), Error> {
        // Add the minijail logging fd to the list of preserved fds to prevent
        // minijail to close it after it execved.
        let mut fds = vec![(self.log_fd.as_raw_fd(), self.log_fd.as_raw_fd())];

        // stdout
        let stdout = if let Some(io) = manifest.io.as_ref().and_then(|io| io.stdout.as_ref()) {
            if *io == Output::Pipe {
                fds.push((1, 1));
                None
            } else {
                let io = Io::new(io).await?;
                fds.push((io.writefd.as_raw_fd(), 1));
                Some(io)
            }
        } else {
            None
        };

        // stderr
        let stderr = if let Some(io) = manifest.io.as_ref().and_then(|io| io.stderr.as_ref()) {
            if *io == Output::Pipe {
                fds.push((2, 2));
                None
            } else {
                let io = Io::new(io).await?;
                fds.push((io.writefd.as_raw_fd(), 2));
                Some(io)
            }
        } else {
            None
        };

        let io = (stdout, stderr);

        Ok((io, fds))
    }

    async fn setup_mounts(
        config: &Config,
        jail: &mut MinijailHandle,
        container: &MountedContainer<MinijailProcess>,
        uid: u32,
        gid: u32,
    ) -> Result<(), Error> {
        let proc = Path::new("/proc");
        jail.mount_bind(&proc, &proc, false)
            .map_err(into_io_error)?;
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
                    jail.mount_bind(&host, &target, rw).map_err(into_io_error)?;
                }
                Mount::Persist => {
                    let dir = config.data_dir.join(&container.manifest.name);
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
                        .map_err(into_io_error)?;
                }
                Mount::Resource { name, version, dir } => {
                    let src = {
                        // Join the source of the resource container with the mount dir
                        let resource_root = config.run_dir.join(format!("{}:{}", name, version));
                        let dir = dir
                            .strip_prefix("/")
                            .map(|d| resource_root.join(d))
                            .unwrap_or(resource_root);

                        if !dir.exists() {
                            return Err(Error::StartContainerFailed(
                                container.container.clone(),
                                format!("Resource folder {} is missing", dir.display()),
                            ));
                        }

                        dir
                    };

                    debug!("Mounting {} on {}", src.display(), target.display());

                    jail.mount_bind(&src, &target, false)
                        .map_err(into_io_error)?;
                }
                Mount::Tmpfs { size } => {
                    debug!(
                        "Mounting tmpfs with size {} on {}",
                        bytesize::ByteSize::b(*size),
                        target.display()
                    );
                    let data = format!("size={},mode=1777", size);
                    jail.mount_with_data(&Path::new("none"), &target, "tmpfs", 0, &data)
                        .map_err(into_io_error)?;
                }
                Mount::Dev { r#type } => {
                    match r#type {
                        // The Full mount of /dev is a simple rw bind mount of /dev
                        Dev::Full => {
                            let dev = Path::new("/dev");
                            jail.mount_bind(&dev, &dev, true).map_err(into_io_error)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Spawn a task that waits for the process to exit. This resolves to the exit status
    /// of `pid`.
    async fn waitpid(
        container: Container,
        pid: Pid,
        event_handle: EventTx,
    ) -> impl Future<Output = Result<ExitStatus, Error>> {
        task::spawn_blocking(move || {
            let pid = unistd::Pid::from_raw(pid as i32);
            let status = loop {
                match wait::waitpid(Some(pid), None) {
                    // The process exited normally (as with exit() or returning from main) with the given exit code.
                    // This case matches the C macro WIFEXITED(status); the second field is WEXITSTATUS(status).
                    Ok(WaitStatus::Exited(pid, code)) => {
                        debug!("Process {} exit code is {}", pid, code);
                        break ExitStatus::Exit(code);
                    }

                    // The process was killed by the given signal.
                    // The third field indicates whether the signal generated a core dump. This case matches the C macro WIFSIGNALED(status); the last two fields correspond to WTERMSIG(status) and WCOREDUMP(status).
                    Ok(WaitStatus::Signaled(pid, signal, _dump)) => {
                        debug!("Process {} exit status is signal {}", pid, signal);
                        break ExitStatus::Signaled(signal);
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
            };

            // Send notification to main loop
            // The send could potentially faild during a shutdown
            if let Err(e) = event_handle.blocking_send(Event::Exit(container, status.clone())) {
                warn!("Failed to send process exit sttus to event loop: {}", e);
            }

            status
        })
        .map_err(|e| {
            Error::Io(
                "Task join error".into(),
                io::Error::new(io::ErrorKind::Other, e),
            )
        })
    }
}

/// We need a Send + Sync version of minijail::Minijail
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

/// A started minijailed process
pub(crate) struct MinijailProcess {
    argv: String,
    /// PID of this process
    pid: Pid,
    /// Exit handle of this process
    exit_status:
        Box<dyn Future<Output = Result<ExitStatus, super::error::Error>> + Unpin + Send + Sync>,
    /// Handle to a libminijail configuration
    _jail: MinijailHandle,
    /// Captured stdout output
    _io: (Option<Io>, Option<Io>),
    /// Debugging facilities
    debug: Debug,
    /// Sync childs execve
    sync: Option<ProcessSync>,
}

impl fmt::Debug for MinijailProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Process").field("pid", &self.pid).finish()
    }
}

#[async_trait]
impl Process for MinijailProcess {
    /// Resume the process
    async fn start(&mut self) -> Result<(), Error> {
        debug!("Starting \"{}\"", self.argv);
        if let Some(sync) = self.sync.take() {
            sync.resume().await?;
        }
        Ok(())
    }

    /// Send a SIGTERM to the application. If the application does not terminate with a timeout
    /// it is SIGKILLed.
    async fn stop(mut self, timeout: time::Duration) -> Result<ExitStatus, super::error::Error> {
        debug!("Trying to send SIGTERM to {}", self.pid);
        let exit_status = match signal::kill(unistd::Pid::from_raw(self.pid as i32), Some(SIGTERM))
        {
            Ok(_) => {
                match time::timeout(timeout, &mut self.exit_status).await {
                    Err(_) => {
                        warn!(
                            "Process {} did not exit within {:?}. Sending SIGKILL...",
                            self.pid, timeout
                        );
                        // Send SIGKILL if the process did not terminate before timeout
                        signal::kill(unistd::Pid::from_raw(self.pid as i32), Some(SIGKILL))
                            .map_err(|e| Error::Os("Failed to kill process".to_string(), e))?;

                        (&mut self.exit_status).await
                    }
                    Ok(exit_status) => exit_status,
                }
            }
            // The proces is terminated already. Wait for the waittask to do it's job and resolve exit_status
            Err(nix::Error::Sys(errno)) if errno == nix::errno::Errno::ESRCH => {
                debug!("Process {} already exited. Waiting for status", self.pid);
                let exit_status = self.exit_status.await?;
                Ok(exit_status)
            }
            Err(e) => Err(Error::Os(format!("Failed to SIGTERM {}", self.pid), e)),
        }?;

        self.debug.destroy().await?;

        Ok(exit_status)
    }

    fn pid(&self) -> Pid {
        self.pid
    }
}

/// Debugging facilities attached to a started container
#[derive(Debug)]
struct Debug {
    strace: Option<process_debug::Strace>,
    perf: Option<process_debug::Perf>,
}

impl Debug {
    /// Start configured debug facilities and attach to `pid`
    async fn from(config: &Config, manifest: &Manifest, pid: Pid) -> Result<Debug, Error> {
        // Attach a strace instance if configured in the runtime configuration
        let strace: OptionFuture<_> = config
            .debug
            .as_ref()
            .and_then(|debug| debug.strace.as_ref())
            .map(|strace| process_debug::Strace::new(strace, manifest, &config.log_dir, pid))
            .into();

        // Attach a perf instance if configured in the runtime configuration
        let perf: OptionFuture<_> = config
            .debug
            .as_ref()
            .and_then(|debug| debug.perf.as_ref())
            .map(|perf| process_debug::Perf::new(perf, manifest, &config.log_dir, pid))
            .into();

        let (strace, perf) = tokio::join!(strace, perf);
        Ok(Debug {
            strace: strace.transpose()?,
            perf: perf.transpose()?,
        })
    }

    /// Shutdown configured debug facilities and attached to `pid`
    async fn destroy(self) -> Result<(), super::error::Error> {
        if let Some(strace) = self.strace {
            strace.destroy().await?;
        }

        if let Some(perf) = self.perf {
            perf.destroy().await?;
        }

        Ok(())
    }
}

#[derive(Debug)]
struct Io {
    writefd: PipeWrite,
    token: CancellationToken,
}

impl Io {
    /// Create a new Io handle
    pub async fn new(io: &Output) -> Result<Io, Error> {
        let (reader, writefd) =
            pipe().map_err(|e| Error::Io("Failed to open pipe".to_string(), e))?;
        let token = CancellationToken::new();

        {
            let token = token.clone();
            let mut io = Self::io(io).await?;

            let mut async_reader: AsyncPipeRead = reader.try_into().map_err(|e| {
                Error::Io(
                    "Failed to get async handler from pipe reader".to_string(),
                    e,
                )
            })?;

            task::spawn(async move {
                let copy = io::copy(&mut async_reader, &mut io);
                select! {
                    r = copy => {
                        match r {
                            Ok(_) => (),
                            Err(e) => unimplemented!("Error handling of output forward: {}", e),
                        }
                    }
                    _ = token.cancelled() => (),
                }
            });
        }

        Ok(Io { writefd, token })
    }

    /// Create a AsyncWrite from the IoOutput configuration
    async fn io(io: &Output) -> Result<Box<dyn AsyncWrite + Unpin + Send>, Error> {
        match io {
            Output::Pipe => unreachable!(),
            Output::Log { level, tag } => Ok(Box::new(Log::new(*level, tag))),
        }
    }
}

impl Drop for Io {
    fn drop(&mut self) {
        // Stop the internally spawned task
        self.token.cancel();
    }
}

/// Wrap the Rust log into a AsyncWrite
struct Log {
    level: Level,
    tag: String,
    buffer: BytesMut,
}

impl Log {
    fn new(level: Level, tag: &str) -> Log {
        Log {
            level,
            tag: tag.to_string(),
            buffer: BytesMut::new(),
        }
    }
}

impl AsyncWrite for Log {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.buffer.extend(buf);
        while let Some(p) = self.buffer.iter().position(|b| *b == b'\n') {
            let line = self.buffer.split_to(p);
            self.buffer.advance(1);
            let line = String::from_utf8_lossy(&line);
            let line = format!("{}: {}", self.tag, line);
            match self.level {
                Level::Trace => trace!("{}", line),
                Level::Debug => debug!("{}", line),
                Level::Info => info!("{}", line),
                Level::Warn => warn!("{}", line),
                Level::Error => error!("{}", line),
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// Suspend the execve call withing a minijail child until resume is called.
/// This is needed in order to not execute any application code before the process
/// is fully setup e.g debugging things like strace or the cgroups setup
/// Wait for the child process to processed the resume command.
struct ProcessSync {
    resume_writer: AsyncPipeWrite,
    ack_reader: AsyncPipeRead,
    resume_reader_fd: RawFd,
    ack_writer_fd: RawFd,

    /// Handle the the Fn passed to minijail which must be freed.
    _hook: ::minijail::HookHandle,
}

impl ProcessSync {
    fn with(jail: &mut MinijailHandle) -> Result<ProcessSync, Error> {
        // Sync the parent and child via a pipe. The readfd is owned by child. The writefd
        // is owned by the parent.
        let (mut resume_reader, resume_writer) =
            pipe().map_err(|e| Error::Io("Failed to create pipe".to_string(), e))?;
        let (ack_reader, mut ack_writer) =
            pipe().map_err(|e| Error::Io("Failed to create pipe".to_string(), e))?;

        let resume_writer: AsyncPipeWrite = resume_writer
            .try_into()
            .map_err(|e| Error::Io("Failed to get async pipe handle".to_string(), e))?;
        let ack_reader: AsyncPipeRead = ack_reader
            .try_into()
            .map_err(|e| Error::Io("Failed to get async pipe handle".to_string(), e))?;

        let resume_reader_fd = resume_reader.as_raw_fd();
        let ack_writer_fd = ack_writer.as_raw_fd();

        // Install a hook in libminijail that block on a `read` until a byte
        // is received. This hook runs as last thing before the execve.
        let execve_hook = move || {
            use std::io::{Read, Write};
            resume_reader
                .read_exact(&mut [0u8; 1])
                .expect("Failed to read on resume pipe");
            ack_writer
                .write_all(&[1])
                .expect("Failed to write on ack pipe");
        };

        // Keep hook
        let hook_handle = jail.add_hook(execve_hook, minijail::Hook::PreExecve);

        Ok(ProcessSync {
            resume_reader_fd,
            resume_writer,
            ack_reader,
            ack_writer_fd,
            _hook: hook_handle,
        })
    }

    /// Provide access to the childs half because this needs to be added
    /// to the list of fds that minijail shall preserve in the child process
    /// and instead of closing.
    fn resume_fd(&self) -> RawFd {
        self.resume_reader_fd
    }

    /// Provide access to the childs half because this needs to be added
    /// to the list of fds that minijail shall preserve in the child process
    /// and instead of closing.
    fn ack_fd(&self) -> RawFd {
        self.ack_writer_fd
    }

    /// Send a byte to the child that might block in the hook.
    async fn resume(mut self) -> Result<(), Error> {
        self.resume_writer
            .write_u8(1)
            .await
            .map_err(|e| Error::Io("Sync".into(), e))
            .map(drop)?;
        self.ack_reader
            .read_exact(&mut [0u8; 1])
            .await
            .map_err(|e| Error::Io("Sync".into(), e))
            .map(drop)
    }
}
