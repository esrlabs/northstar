use std::os::unix::{
    net::UnixStream,
    prelude::{FromRawFd, OwnedFd},
};

use crate::{
    common::container::Container,
    npk::manifest::{self, io::Output},
};
use log::debug;
use nix::{
    fcntl::OFlag,
    libc::{STDERR_FILENO, STDOUT_FILENO},
    sys::stat::Mode,
    unistd::dup,
};
use tokio::{
    io::{self, AsyncBufReadExt},
    task::{self, JoinHandle},
};

pub struct ContainerIo {
    pub io: [OwnedFd; 3],
    /// A handle to the io forwarding task if stdout or stderr is set to `Output::Pipe`
    pub task: Option<JoinHandle<io::Result<()>>>,
}

/// Create a new pty handle if configured in the manifest or open /dev/null instead.
pub async fn open(container: &Container, io: &manifest::io::Io) -> io::Result<ContainerIo> {
    debug!(
        "Container {} stdout is {}",
        container,
        serde_plain::to_string(&io.stdout).expect("internal error")
    );
    debug!(
        "Container {} stderr is {}",
        container,
        serde_plain::to_string(&io.stderr).expect("internal error")
    );

    // Open dev null - needed in any case for stdin
    let dev_null = nix::fcntl::open("/dev/null", OFlag::O_RDWR, Mode::empty())
        .map_err(|err| io::Error::from_raw_os_error(err as i32))
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })?;

    // Don't start the output task if stdout and stderr are configured to be discarded
    if io.stdout == Output::Discard && io.stderr == Output::Discard {
        return Ok(ContainerIo {
            io: [dev_null.try_clone()?, dev_null.try_clone()?, dev_null],
            task: None,
        });
    }

    // Don't start the output task if stdout and stderr shall be inherited
    if io.stdout == Output::Inherit && io.stderr == Output::Inherit {
        let io = [dev_null, stdout_dup()?, stderr_dup()?];
        return Ok(ContainerIo { io, task: None });
    }

    fn stdout_dup() -> io::Result<OwnedFd> {
        Ok(unsafe { OwnedFd::from_raw_fd(dup(STDOUT_FILENO)?) })
    }
    fn stderr_dup() -> io::Result<OwnedFd> {
        Ok(unsafe { OwnedFd::from_raw_fd(dup(STDERR_FILENO)?) })
    }

    // Convert UnixStream into OwnedFd.
    let (read, write) = UnixStream::pair()?;
    let write = write.into();
    let (stdout, stderr) = match (&io.stdout, &io.stderr) {
        (Output::Discard, Output::Pipe) => (dev_null.try_clone()?, write),
        (Output::Pipe, Output::Discard) => (write, dev_null.try_clone()?),

        (Output::Inherit, Output::Pipe) => (stdout_dup()?, write),
        (Output::Pipe, Output::Inherit) => (write, stderr_dup()?),

        (Output::Inherit, Output::Discard) => (stdout_dup()?, dev_null.try_clone()?),
        (Output::Discard, Output::Inherit) => (dev_null.try_clone()?, stderr_dup()?),

        (Output::Pipe, Output::Pipe) => (write.try_clone()?, write),
        _ => unreachable!(),
    };

    let task = task::spawn(log_lines(container.to_string(), read));
    let io = [dev_null, stdout, stderr];

    Ok(ContainerIo {
        io,
        task: Some(task),
    })
}

/// Pipe task: Read pty until stop is cancelled. Write linewist to `log`.
async fn log_lines(target: String, stream: UnixStream) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    let stream = tokio::net::UnixStream::from_std(stream)?;

    let mut lines = io::BufReader::new(stream).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        log::debug!(target: &target, "{}", line);
    }

    Ok(())
}
