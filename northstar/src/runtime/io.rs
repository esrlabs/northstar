use std::{
    os::unix::prelude::{AsRawFd, FromRawFd, IntoRawFd},
    path::{Path, PathBuf},
};

use crate::{
    common::container::Container,
    npk::manifest::{self, io::Output},
};
use log::debug;
use nix::{
    fcntl::OFlag,
    pty,
    sys::{stat::Mode, termios::SetArg},
};
use tokio::{
    io::{self, AsyncBufReadExt, AsyncRead},
    task::{self, JoinHandle},
};

use super::ipc::owned_fd::{OwnedFd, OwnedFdRw};

pub struct ContainerIo {
    pub io: [OwnedFd; 3],
    /// A handle to the io forwarding task if stdout or stderr is set to `Output::Pipe`
    pub log_task: Option<JoinHandle<io::Result<()>>>,
}

/// Create a new pty handle if configured in the manifest or open /dev/null instead.
pub async fn open(container: &Container, io: &manifest::io::Io) -> io::Result<ContainerIo> {
    // Open dev null - needed in any case for stdin
    let dev_null = openrw("/dev/null")?;

    // Don't start the output task if it is configured to be discarded
    if io.stdout == Output::Discard && io.stderr == Output::Discard {
        return Ok(ContainerIo {
            io: [dev_null.clone()?, dev_null.clone()?, dev_null],
            log_task: None,
        });
    }

    debug!("Spawning output logging task for {}", container);
    let (write, read) = output_device(OutputDevice::Socket)?;

    let log_target = format!("northstar::{}", container);
    let log_task = task::spawn(log_lines(log_target, read));

    let (stdout, stderr) = match (&io.stdout, &io.stderr) {
        (Output::Discard, Output::Pipe) => (dev_null.clone()?, write),
        (Output::Pipe, Output::Discard) => (write, dev_null.clone()?),
        (Output::Pipe, Output::Pipe) => (write.clone()?, write),
        _ => unreachable!(),
    };

    let io = [dev_null, stdout, stderr];

    Ok(ContainerIo {
        io,
        log_task: Some(log_task),
    })
}

/// Type of output device
enum OutputDevice {
    Socket,
    #[allow(dead_code)]
    Pty,
}

/// Open a device used to collect the container output and forward it to Northstar's log
fn output_device(
    dev: OutputDevice,
) -> io::Result<(OwnedFd, Box<dyn AsyncRead + Unpin + Send + Sync + 'static>)> {
    match dev {
        OutputDevice::Socket => {
            let (msock, csock) = std::os::unix::net::UnixStream::pair()?;
            let msock = {
                msock.set_nonblocking(true)?;
                tokio::net::UnixStream::from_std(msock)?
            };
            Ok((csock.into(), Box::new(msock)))
        }
        OutputDevice::Pty => {
            let (main, sec_path) = openpty();
            Ok((openrw(sec_path)?, Box::new(OwnedFdRw::new(main)?)))
        }
    }
}

/// Open a path for reading and writing.
fn openrw<T: AsRef<Path>>(f: T) -> io::Result<OwnedFd> {
    nix::fcntl::open(f.as_ref(), OFlag::O_RDWR, Mode::empty())
        .map_err(|err| io::Error::from_raw_os_error(err as i32))
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Create a new pty and return the main fd along with the sub name.
fn openpty() -> (OwnedFd, PathBuf) {
    let main = pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_NONBLOCK)
        .expect("failed to open pty");

    nix::sys::termios::tcgetattr(main.as_raw_fd())
        .map(|mut termios| {
            nix::sys::termios::cfmakeraw(&mut termios);
            termios
        })
        .and_then(|termios| {
            nix::sys::termios::tcsetattr(main.as_raw_fd(), SetArg::TCSANOW, &termios)
        })
        .and_then(|_| pty::grantpt(&main))
        .and_then(|_| pty::unlockpt(&main))
        .expect("failed to configure pty");

    // Get the name of the sub
    let sub = pty::ptsname_r(&main)
        .map(PathBuf::from)
        .expect("failed to get PTY sub name");

    debug!("Created PTY {}", sub.display());
    let main = unsafe { OwnedFd::from_raw_fd(main.into_raw_fd()) };

    (main, sub)
}

/// Pipe task: Read pty until stop is cancelled. Write linewist to `log`.
async fn log_lines<R: AsyncRead + Unpin>(target: String, output: R) -> io::Result<()> {
    let mut lines = io::BufReader::new(output).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        log::debug!(target: &target, "{}", line);
    }

    Ok(())
}
