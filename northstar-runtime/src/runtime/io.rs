use std::os::unix::{
    net::UnixStream as StdUnixStream,
    prelude::{FromRawFd, OwnedFd},
};

use crate::{
    common::container::Container,
    npk::manifest::{self, io::Output},
};
use log::debug;
use nix::{fcntl::OFlag, sys::stat::Mode};
use tokio::{
    io::{self, copy_buf, AsyncBufReadExt, AsyncWrite},
    net::UnixStream,
    task::{self},
};

/// Buffer size for stdout/stderr forwarding
const BUFFER_SIZE: usize = 16 * 4048;

pub struct ContainerIo {
    pub io: [OwnedFd; 3],
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
    let stdout = forward(&io.stdout, &dev_null, container, tokio::io::stdout())?;
    let stderr = forward(&io.stderr, &dev_null, container, tokio::io::stderr())?;
    let io = [dev_null, stdout, stderr];

    Ok(ContainerIo { io })
}

/// Spawn a task that forwards stdout/stderr to the logging system or stdout/stderr
fn forward<W: AsyncWrite + Send + Sync + Unpin + 'static>(
    destination: &Output,
    dev_null: &OwnedFd,
    container: &Container,
    mut out: W,
) -> io::Result<OwnedFd> {
    match destination {
        Output::Discard => dev_null.try_clone(),
        Output::Pipe => {
            let (read, write) = StdUnixStream::pair()?;
            read.set_nonblocking(true)?;
            let mut lines = io::BufReader::new(UnixStream::from_std(read)?).lines();
            let target = container.to_string();
            task::spawn(async move {
                while let Ok(Some(line)) = lines.next_line().await {
                    log::debug!(target: &target, "{}", line);
                }
            });
            Ok(write.into())
        }
        Output::Inherit => {
            let (read, write) = StdUnixStream::pair()?;
            read.set_nonblocking(true)?;
            let mut read = io::BufReader::with_capacity(BUFFER_SIZE, UnixStream::from_std(read)?);
            task::spawn(async move { copy_buf(&mut read, &mut out).await });
            Ok(write.into())
        }
    }
}
