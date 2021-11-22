use std::{io, io::Result, os::unix::prelude::AsRawFd};

use nix::fcntl;

/// Sets O_NONBLOCK flag on self
pub trait RawFdExt: AsRawFd {
    fn set_nonblocking(&self);
    fn set_blocking(&self);
    fn set_cloexec(&self, value: bool) -> Result<()>;
}

impl<T: AsRawFd> RawFdExt for T {
    fn set_nonblocking(&self) {
        unsafe {
            let opt = nix::libc::fcntl(self.as_raw_fd(), nix::libc::F_GETFL);
            nix::libc::fcntl(
                self.as_raw_fd(),
                nix::libc::F_SETFL,
                opt | nix::libc::O_NONBLOCK,
            );
        }
    }

    fn set_blocking(&self) {
        unsafe {
            let opt = nix::libc::fcntl(self.as_raw_fd(), nix::libc::F_GETFL);
            nix::libc::fcntl(
                self.as_raw_fd(),
                nix::libc::F_SETFL,
                opt & !nix::libc::O_NONBLOCK,
            );
        }
    }

    fn set_cloexec(&self, value: bool) -> Result<()> {
        let flags = fcntl::fcntl(self.as_raw_fd(), fcntl::FcntlArg::F_GETFD)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let mut flags = fcntl::FdFlag::from_bits(flags).unwrap();
        flags.set(fcntl::FdFlag::FD_CLOEXEC, value);

        fcntl::fcntl(self.as_raw_fd(), fcntl::FcntlArg::F_SETFD(flags))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            .map(drop)
    }
}
