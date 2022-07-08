//! Owned Unix-like file descriptors.

use std::{
    fmt,
    os::unix::prelude::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
};

use nix::{libc, unistd::dup};
use std::io;

/// Owned raw fd that closes on drop.
pub struct OwnedFd {
    inner: RawFd,
}

impl OwnedFd {
    #[inline]
    pub fn clone(&self) -> io::Result<Self> {
        dup(self.inner)
            .map(|inner| Self { inner })
            .map_err(|err| io::Error::from_raw_os_error(err as i32))
    }
}

impl AsRawFd for OwnedFd {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.inner
    }
}

impl IntoRawFd for OwnedFd {
    #[inline]
    fn into_raw_fd(self) -> RawFd {
        self.inner
    }
}

impl FromRawFd for OwnedFd {
    /// Constructs a new instance of `Self` from the given raw file descriptor.
    ///
    /// # Safety
    ///
    /// The resource pointed to by `fd` must be open and suitable for assuming
    /// ownership. The resource must not require any cleanup other than `close`.
    #[inline]
    unsafe fn from_raw_fd(inner: RawFd) -> Self {
        assert_ne!(inner, u32::MAX as RawFd);
        Self { inner }
    }
}

impl Drop for OwnedFd {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            // Note that errors are ignored when closing a file descriptor. The
            // reason for this is that if an error occurs we don't actually know if
            // the file descriptor was closed or not, and if we retried (for
            // something like EINTR), we might close another valid file descriptor
            // opened after we closed ours.
            let _ = libc::close(self.inner);
        }
    }
}

impl fmt::Debug for OwnedFd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedFd").field("fd", &self.inner).finish()
    }
}

impl From<std::os::unix::net::UnixStream> for OwnedFd {
    #[inline]
    fn from(stream: std::os::unix::net::UnixStream) -> Self {
        unsafe { Self::from_raw_fd(stream.into_raw_fd()) }
    }
}
