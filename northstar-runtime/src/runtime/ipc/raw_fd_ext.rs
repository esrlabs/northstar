use nix::fcntl;
use std::{io, io::Result, os::unix::prelude::AsRawFd};

pub trait RawFdExt: AsRawFd {
    /// Returns true of self is set to non-blocking.
    fn is_nonblocking(&self) -> Result<bool>;

    /// Set non-blocking mode.
    fn set_nonblocking(&self, value: bool) -> Result<()>;
}

impl<T: AsRawFd> RawFdExt for T {
    fn is_nonblocking(&self) -> Result<bool> {
        let flags = fcntl::fcntl(self.as_raw_fd(), fcntl::FcntlArg::F_GETFL)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(flags & fcntl::OFlag::O_NONBLOCK.bits() != 0)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let flags = fcntl::fcntl(self.as_raw_fd(), fcntl::FcntlArg::F_GETFL)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut flags = fcntl::OFlag::from_bits_truncate(flags);
        flags.set(fcntl::OFlag::O_NONBLOCK, nonblocking);

        fcntl::fcntl(self.as_raw_fd(), fcntl::FcntlArg::F_SETFL(flags))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            .map(drop)
    }
}

#[test]
#[allow(clippy::unwrap_used)]
fn non_blocking() {
    let (a, b) = nix::unistd::pipe().unwrap();
    drop(b);

    let opt = unsafe { nix::libc::fcntl(a.as_raw_fd(), nix::libc::F_GETFL) };
    assert!((dbg!(opt) & nix::libc::O_NONBLOCK) == 0);
    assert!(!a.is_nonblocking().unwrap());

    a.set_nonblocking(true).unwrap();
    let opt = unsafe { nix::libc::fcntl(a.as_raw_fd(), nix::libc::F_GETFL) };
    assert!((dbg!(opt) & nix::libc::O_NONBLOCK) != 0);
    assert!(a.is_nonblocking().unwrap());

    a.set_nonblocking(false).unwrap();
    let opt = unsafe { nix::libc::fcntl(a.as_raw_fd(), nix::libc::F_GETFL) };
    assert!((dbg!(opt) & nix::libc::O_NONBLOCK) == 0);
    assert!(!a.is_nonblocking().unwrap());
}
