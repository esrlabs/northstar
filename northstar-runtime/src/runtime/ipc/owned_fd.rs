//! Owned Unix-like file descriptors.

use std::{
    fmt,
    io::ErrorKind,
    os::unix::prelude::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    pin::Pin,
    task::{Context, Poll},
};

use nix::{libc, unistd::dup};
use std::io;
use tokio::io::{unix::AsyncFd, AsyncRead, AsyncWrite, ReadBuf};

use super::RawFdExt;

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

pub struct OwnedFdRw {
    inner: AsyncFd<OwnedFd>,
}

impl OwnedFdRw {
    pub fn new(inner: OwnedFd) -> io::Result<Self> {
        inner.set_nonblocking(true)?;
        AsyncFd::new(inner).map(|inner| Self { inner })
    }
}

impl AsRawFd for OwnedFdRw {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl AsyncRead for OwnedFdRw {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut ready = match self.inner.poll_read_ready(cx) {
                Poll::Ready(x) => x?,
                Poll::Pending => return Poll::Pending,
            };

            let ret = unsafe {
                nix::libc::read(
                    self.as_raw_fd(),
                    buf.unfilled_mut() as *mut _ as _,
                    buf.remaining(),
                )
            };

            return if ret < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == ErrorKind::WouldBlock {
                    ready.clear_ready();
                    continue;
                } else {
                    Poll::Ready(Err(e))
                }
            } else {
                let n = ret as usize;
                unsafe { buf.assume_init(n) };
                buf.advance(n);
                Poll::Ready(Ok(()))
            };
        }
    }
}

impl AsyncWrite for OwnedFdRw {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut ready = match self.inner.poll_write_ready(cx) {
                Poll::Ready(x) => x?,
                Poll::Pending => return Poll::Pending,
            };

            let ret = unsafe { nix::libc::write(self.as_raw_fd(), buf.as_ptr() as _, buf.len()) };

            return if ret < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == ErrorKind::WouldBlock {
                    ready.clear_ready();
                    continue;
                } else {
                    Poll::Ready(Err(e))
                }
            } else {
                Poll::Ready(Ok(ret as usize))
            };
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
