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
    process::{waitpid, Error, ExitStatus, Pid, ENV_NAME, ENV_VERSION},
    process_debug::{Perf, Strace},
    state::Container,
};
use crate::runtime::EventTx;
use bytes::{Buf, BytesMut};
use futures::Future;
use itertools::Itertools;
use log::{debug, error, info, trace, warn, Level};
use nix::{
    fcntl::{self, fcntl, OFlag},
    sys::signal,
    unistd::{self, chown, close, pipe},
};
use npk::manifest::{Dev, Manifest, Mount, MountFlag, Output};
use signal::Signal::{SIGKILL, SIGTERM};
use std::{
    fmt, iter, ops,
    os::unix::prelude::*,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
    unimplemented,
};
use tokio::{
    fs,
    io::{self, unix::AsyncFd, AsyncBufReadExt, AsyncRead, AsyncWrite, ReadBuf},
    select, task, time,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub struct Minijail<'a> {
    log_fd: i32,
    event_tx: EventTx,
    config: &'a Config,
}

impl<'a> Minijail<'a> {
    /// Initialize minijail
    pub(crate) fn new(event_tx: EventTx, config: &'a Config) -> Result<Minijail<'a>, Error> {
        let pipe = AsyncPipe::new()?;
        let log_fd = pipe.blocking_fd();
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
            config,
            log_fd,
        })
    }

    /// Shutdown minijail
    pub(crate) fn shutdown(&self) -> Result<(), Error> {
        close(self.log_fd).map_err(|e| Error::Os("Failed to close log_fd".into(), e))?;
        Ok(())
    }

    /// Create a new minijailed process which is forked and blocks before execve. Start it with Process::start.
    pub(crate) async fn create(&self, container: &Container) -> Result<Process, Error> {
        let root = &container.root;
        let manifest = &container.manifest;
        let mut jail = MinijailHandle(::minijail::Minijail::new().map_err(Error::Minijail)?);

        let init = manifest
            .init
            .as_ref()
            .ok_or_else(|| Error::Start("Cannot start a resource".to_string()))?;

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
                .map_err(Error::Minijail)?;
        }

        // Update the supplementary group list if specified
        if let Some(suppl_groups) = &manifest.suppl_groups {
            // TODO: the groups should be passed an array
            jail.update_suppl_groups(&suppl_groups.join(" "))
                .map_err(Error::Minijail)?;
        }

        // Make the process enter a pid namespace
        jail.namespace_pids();

        // Make the process enter a vfs namespace
        jail.namespace_vfs();
        // Set no_new_privs. See </kernel/seccomp.c> and </kernel/sys.c>
        // in the kernel source tree for an explanation of the parameters.
        jail.no_new_privs();
        // Set chroot dir for process
        jail.enter_chroot(&root.as_path())?;

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

        // Construct the io objects configured in the manifest toghether with the log_fd
        // that needs to be preserved.
        let (io, mut fds) = self.inheritable_fds(&manifest).await?;

        // Create a child sync
        let sync = ProcessSync::with(&mut jail)?;
        // Add the sync fd to the list of preserved fds
        fds.push((sync.child_fd(), sync.child_fd()));

        // And finally start it....
        let argv_str = argv.iter().join(" ");
        debug!("Preparing \"{}\"", argv_str);
        let pid = jail.run_remap_env_preload(&init.as_path(), &fds, &argv, &env, false)? as u32;

        // Attach debug tools if configured in the runtime configuration.
        let debug = Debug::from(&self.config, &manifest, pid).await?;

        // Spawn a task thats waits for the child to exit
        let exit_status = Box::new(Box::pin(
            waitpid(&manifest.name, pid, self.event_tx.clone()).await,
        ));

        Ok(Process {
            argv: argv_str,
            pid,
            _jail: jail,
            _io: io,
            exit_status,
            debug,
            sync: Some(sync),
        })
    }

    /// Configure stdout/stderr as declared in the manifest and return list of fds that
    /// shall be preserved by minijail for the spanwed process
    async fn inheritable_fds(
        &self,
        manifest: &Manifest,
    ) -> Result<((Option<Io>, Option<Io>), Vec<(i32, i32)>), Error> {
        // Add the minijail logging fd to the list of preserved fds to prevent
        // minijail to close it after it execved.
        let mut fds = vec![(self.log_fd, self.log_fd)];

        // stdout
        let stdout = if let Some(io) = manifest.io.as_ref().and_then(|io| io.stdout.as_ref()) {
            if *io == Output::Pipe {
                fds.push((1, 1));
                None
            } else {
                let io = Io::new(io).await?;
                fds.push((io.writefd, 1));
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
                fds.push((io.writefd, 2));
                Some(io)
            }
        } else {
            None
        };

        let io = (stdout, stderr);

        Ok((io, fds))
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
                    let dir = self.config.data_dir.join(&container.manifest.name);
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
                        let resource_root =
                            self.config.run_dir.join(&name).join(&version.to_string());
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
pub(crate) struct Process {
    argv: String,
    /// PID of this process
    pid: Pid,
    /// Exit handle of this process
    exit_status: Box<dyn Future<Output = Result<ExitStatus, Error>> + Unpin + Send + Sync>,
    /// Handle to a libminijail configuration
    _jail: MinijailHandle,
    /// Captured stdout output
    _io: (Option<Io>, Option<Io>),
    /// Debugging facilities
    debug: Debug,
    /// Sync childs execve
    sync: Option<ProcessSync>,
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

    /// Resume the process
    pub async fn start(&mut self) -> Result<(), Error> {
        debug!("Starting \"{}\"", self.argv);
        if let Some(sync) = self.sync.take() {
            sync.resume().await?;
        }
        Ok(())
    }

    pub async fn terminate(&mut self, timeout: time::Duration) -> Result<ExitStatus, Error> {
        // Send a SIGTERM to the application. If the application does not terminate with a timeout
        // it is SIGKILLed.
        signal::kill(unistd::Pid::from_raw(self.pid as i32), Some(SIGTERM))
            .map_err(|e| Error::Os(format!("Failed to SIGTERM {}", self.pid), e))?;

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

    pub async fn destroy(self) -> Result<(), Error> {
        self.debug.destroy().await
    }
}

/// Debugging facilities attached to a started container
#[derive(Debug)]
struct Debug {
    strace: Option<Strace>,
    perf: Option<Perf>,
}

impl Debug {
    /// Start configured debug facilities and attach to `pid`
    async fn from(config: &Config, manifest: &Manifest, pid: u32) -> Result<Debug, Error> {
        // Attach a strace instance if configured in the runtime configuration
        let strace = if let Some(strace) = config
            .debug
            .as_ref()
            .and_then(|debug| debug.strace.as_ref())
        {
            Some(Strace::new(strace, manifest, &config.log_dir, pid).await?)
        } else {
            None
        };

        // Attach a perf instance if configured in the runtime configuration
        let perf = if let Some(perf) = config.debug.as_ref().and_then(|debug| debug.perf.as_ref()) {
            Some(Perf::new(perf, manifest, &config.log_dir, pid).await?)
        } else {
            None
        };

        Ok(Debug { strace, perf })
    }

    /// Shutdown configured debug facilities and attached to `pid`
    async fn destroy(self) -> Result<(), Error> {
        if let Some(strace) = self.strace {
            strace.destroy().await?;
        }

        if let Some(perf) = self.perf {
            perf.destroy().await?;
        }

        Ok(())
    }
}

/// Pipe with async tokio impls
#[derive(Debug)]
struct AsyncPipe {
    non_blocking: AsyncFd<std::fs::File>,
    blocking: RawFd,
}

impl AsyncPipe {
    fn new() -> Result<AsyncPipe, Error> {
        let (non_blocking, blocking) =
            pipe().map_err(|e| Error::Os("Failed to create pipe".to_string(), e))?;

        let mut flags =
            OFlag::from_bits(fcntl(non_blocking, fcntl::FcntlArg::F_GETFL).unwrap()).unwrap();
        flags.set(OFlag::O_NONBLOCK, true);
        fcntl(non_blocking, fcntl::FcntlArg::F_SETFL(flags)).expect("Failed to configure pipe fd");
        let non_blocking = unsafe { std::fs::File::from_raw_fd(non_blocking) };
        let non_blocking =
            AsyncFd::new(non_blocking).map_err(|e| Error::Io("Async fd".to_string(), e))?;

        Ok(AsyncPipe {
            non_blocking,
            blocking,
        })
    }

    fn blocking_fd(&self) -> RawFd {
        self.blocking
    }
}

impl Drop for AsyncPipe {
    fn drop(&mut self) {
        unistd::close(self.blocking).ok();
    }
}

impl AsyncRead for AsyncPipe {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = futures::ready!(self.non_blocking.poll_read_ready(cx))?;
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

#[derive(Debug)]
struct Io {
    writefd: i32,
    token: CancellationToken,
}

impl Io {
    /// Create a new Io handle
    pub async fn new(io: &Output) -> Result<Io, Error> {
        let mut pipe = AsyncPipe::new()?;
        let writefd = pipe.blocking_fd();
        let token = CancellationToken::new();

        {
            let token = token.clone();
            let mut io = Self::io(io).await?;

            task::spawn(async move {
                let copy = io::copy(&mut pipe, &mut io);
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
struct ProcessSync {
    /// Parent half
    parent: RawFd,
    /// Childs half
    child: RawFd,
    /// Handle the the Fn passed to minijail which must be freed.
    _hook: ::minijail::HookHandle,
}

impl ProcessSync {
    fn with(jail: &mut MinijailHandle) -> Result<ProcessSync, Error> {
        // Sync the parent and child via a pipe. The readfd is owned by child. The writefd
        // is owned by the parent.
        let (childfd, parentfd) =
            pipe().map_err(|e| Error::Os("Failed to create pipe".to_string(), e))?;

        // Install a hook in libminijail that block on a `read` until two bytes
        // are received. This hook runs as last thing before the execve.
        let execve_hook = move || {
            // Block until a byte is read of the pipe is closed.
            unistd::read(childfd, &mut [0u8; 1]).ok();
            // The parent fd is already closed because it's not added to the list of
            // inheritable fds. But close the child half:
            unistd::close(childfd).expect("Failed to close sync fd");
        };

        // Keep hook
        let hook_handle = jail.add_hook(execve_hook, minijail::Hook::PreExecve);

        Ok(ProcessSync {
            parent: parentfd,
            child: childfd,
            _hook: hook_handle,
        })
    }

    /// Provide access to the childs half because this needs to be added
    /// to the list of fds that minijail shall preserve in the child process
    /// and instead of closing.
    fn child_fd(&self) -> RawFd {
        self.child.as_raw_fd()
    }

    /// Send a byte to the child that might block in the hook.
    async fn resume(self) -> Result<(), Error> {
        unistd::write(self.parent, &[0u8; 1])
            .map_err(|e| Error::Os("Sync".into(), e))
            .map(drop)
    }
}

impl Drop for ProcessSync {
    fn drop(&mut self) {
        unistd::close(self.child).expect("Failed to close child");
        unistd::close(self.parent).expect("Failed to close parentfd");
    }
}
