use futures::ready;
use nix::{fcntl, unistd};
use std::{
    convert::{TryFrom, TryInto},
    io,
    io::Result,
    mem,
    os::unix::io::{AsRawFd, IntoRawFd, RawFd},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{unix::AsyncFd, AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

#[derive(Debug)]
struct Inner {
    fd: RawFd,
}

impl Drop for Inner {
    fn drop(&mut self) {
        unistd::close(self.fd).ok();
    }
}

impl From<RawFd> for Inner {
    fn from(fd: RawFd) -> Self {
        Inner { fd }
    }
}

/// Opens a pipe(2) with both ends blocking
pub(crate) fn pipe() -> Result<(PipeRead, PipeWrite)> {
    unistd::pipe().map_err(from_nix).map(|(read, write)| {
        (
            PipeRead {
                inner: Arc::new(read.into()),
            },
            PipeWrite {
                inner: Arc::new(write.into()),
            },
        )
    })
}

/// Read end of a pipe(2). Last dropped clone closes the pipe
#[derive(Clone, Debug)]
pub(crate) struct PipeRead {
    inner: Arc<Inner>,
}

impl io::Read for PipeRead {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        unistd::read(self.as_raw_fd(), buf).map_err(from_nix)
    }
}

impl AsRawFd for PipeRead {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.fd
    }
}

impl IntoRawFd for PipeRead {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.inner.fd;
        mem::forget(self);
        fd
    }
}

/// Write end of a pipe(2). Last dropped clone closes the pipe
#[derive(Clone, Debug)]
pub(crate) struct PipeWrite {
    inner: Arc<Inner>,
}

impl io::Write for PipeWrite {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        unistd::write(self.as_raw_fd(), buf).map_err(from_nix)
    }

    fn flush(&mut self) -> Result<()> {
        unistd::fsync(self.as_raw_fd()).map_err(from_nix)
    }
}

impl AsRawFd for PipeWrite {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.fd
    }
}

impl IntoRawFd for PipeWrite {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.inner.fd;
        mem::forget(self);
        fd
    }
}

/// Pipe's synchronous reading end
#[derive(Debug)]
pub(crate) struct AsyncPipeRead {
    inner: AsyncFd<PipeRead>,
}

impl TryFrom<PipeRead> for AsyncPipeRead {
    type Error = io::Error;

    fn try_from(reader: PipeRead) -> Result<Self> {
        reader.set_nonblocking();
        Ok(AsyncPipeRead {
            inner: AsyncFd::new(reader)?,
        })
    }
}

impl AsyncRead for AsyncPipeRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // map nix::Error to io::Error
                match unistd::read(fd, buf.initialized_mut()) {
                    Ok(n) => Ok(n),
                    // read(2) on a nonblocking file (O_NONBLOCK) returns EAGAIN or EWOULDBLOCK in
                    // case that the read would block. That case is handled by `try_io`.
                    Err(e) => Err(from_nix(e)),
                }
            }) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => {
                    return Poll::Ready(Err(e));
                }
                Err(_would_block) => continue,
            }
        }
    }
}

/// Pipe's asynchronous writing end
#[derive(Debug)]
pub(crate) struct AsyncPipeWrite {
    inner: AsyncFd<PipeWrite>,
}

impl TryFrom<PipeWrite> for AsyncPipeWrite {
    type Error = io::Error;

    fn try_from(write: PipeWrite) -> Result<Self> {
        write.set_nonblocking();
        Ok(AsyncPipeWrite {
            inner: AsyncFd::new(write)?,
        })
    }
}

impl AsyncWrite for AsyncPipeWrite {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready(cx))?;
            match guard.try_io(|inner| unistd::write(inner.as_raw_fd(), buf).map_err(from_nix)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }
}

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

/// Maps an nix::Error to a io::Error
fn from_nix(error: nix::Error) -> io::Error {
    match error {
        nix::Error::Sys(e) => io::Error::from_raw_os_error(e as i32),
        e => io::Error::new(io::ErrorKind::Other, e),
    }
}

#[allow(unused)]
#[derive(Debug)]
pub(crate) struct Condition {
    read: PipeRead,
    write: PipeWrite,
}

#[allow(unused)]
impl Condition {
    pub(crate) fn new() -> Result<Condition> {
        let (rfd, wfd) = pipe()?;

        Ok(Condition {
            read: rfd,
            write: wfd,
        })
    }

    pub(crate) fn set_cloexec(&self) {
        self.read.set_cloexec(true);
        self.write.set_cloexec(true);
    }

    pub(crate) fn wait(mut self) {
        drop(self.write);
        let buf: &mut [u8] = &mut [0u8; 1];
        use std::io::Read;
        loop {
            match self.read.read(buf) {
                Ok(n) if n == 0 => break,
                Ok(_) => continue,
                Err(e) => break,
            }
        }
    }

    pub(crate) fn notify(self) {}

    pub(crate) fn split(self) -> (ConditionWait, ConditionNotify) {
        (
            ConditionWait { read: self.read },
            ConditionNotify { write: self.write },
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ConditionWait {
    read: PipeRead,
}

impl ConditionWait {
    #[allow(unused)]
    pub(crate) fn wait(mut self) {
        use std::io::Read;
        loop {
            match self.read.read(&mut [0u8; 1]) {
                Ok(n) if n == 0 => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }

    pub(crate) async fn async_wait(self) {
        let mut read: AsyncPipeRead = self.read.try_into().unwrap();
        loop {
            match read.read(&mut [0u8; 1]).await {
                Ok(n) if n == 0 => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }
}

impl AsRawFd for ConditionWait {
    fn as_raw_fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }
}

impl IntoRawFd for ConditionWait {
    fn into_raw_fd(self) -> RawFd {
        self.read.into_raw_fd()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ConditionNotify {
    write: PipeWrite,
}

impl ConditionNotify {
    #[allow(unused)]
    pub(crate) fn notify(self) {
        drop(self.write)
    }
}

impl AsRawFd for ConditionNotify {
    fn as_raw_fd(&self) -> RawFd {
        self.write.as_raw_fd()
    }
}

impl IntoRawFd for ConditionNotify {
    fn into_raw_fd(self) -> RawFd {
        self.write.into_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        convert::TryInto,
        io::{Read, Write},
        process, thread,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    /// Smoke test
    fn smoke() {
        let (mut read, mut write) = pipe().unwrap();

        write.write(b"Hello").unwrap();

        let mut buf = [0u8; 5];
        read.read_exact(&mut buf).unwrap();

        assert_eq!(&buf, b"Hello");
    }

    #[test]
    /// Closing the write end must produce EOF on the read end
    fn close() {
        let (mut read, mut write) = pipe().unwrap();

        write.write(b"Hello").unwrap();
        drop(write);

        let mut buf = String::new();
        // Read::read_to_string reads until EOF
        read.read_to_string(&mut buf).unwrap();

        assert_eq!(&buf, "Hello");
    }

    #[test]
    #[should_panic]
    /// Dropping the write end must reault in an EOF
    fn drop_writer() {
        let (mut read, write) = pipe().unwrap();
        drop(write);
        assert!(matches!(read.read_exact(&mut [0u8; 1]), Ok(())));
    }

    #[test]
    #[should_panic]
    /// Dropping the read end must reault in an error on write
    fn drop_reader() {
        let (read, mut write) = pipe().unwrap();
        drop(read);
        loop {
            write.write_all(b"test").expect("Failed to send");
        }
    }

    #[test]
    /// Read and write bytes
    fn read_write() {
        let (mut read, mut write) = pipe().unwrap();

        let writer = thread::spawn(move || {
            for n in 0..=65535u32 {
                write.write(&n.to_be_bytes()).unwrap();
            }
        });

        let mut buf = [0u8; 4];
        for n in 0..=65535u32 {
            read.read_exact(&mut buf).unwrap();
            assert_eq!(buf, n.to_be_bytes());
        }

        writer.join().unwrap();
    }

    #[tokio::test]
    /// Test async version of read and write
    async fn r#async() {
        let (read, write) = pipe().unwrap();

        let mut read: AsyncPipeRead = read.try_into().unwrap();
        let mut write: AsyncPipeWrite = write.try_into().unwrap();

        let write = tokio::spawn(async move {
            for n in 0..=65535u32 {
                write.write(&n.to_be_bytes()).await.unwrap();
            }
        });

        let mut buf = [0u8; 4];
        for n in 0..=65535u32 {
            read.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, n.to_be_bytes());
        }

        write.await.unwrap()
    }

    #[test]
    /// Fork test
    fn fork() {
        let (mut read, mut write) = pipe().unwrap();

        match unsafe { unistd::fork().unwrap() } {
            unistd::ForkResult::Parent { child } => {
                drop(read);
                for n in 0..=65535u32 {
                    write.write(&n.to_be_bytes()).unwrap();
                }
                nix::sys::wait::waitpid(child, None).ok();
            }
            unistd::ForkResult::Child => {
                drop(write);
                let mut buf = [0u8; 4];
                for n in 0..=65535u32 {
                    read.read_exact(&mut buf).unwrap();
                    assert_eq!(buf, n.to_be_bytes());
                }
                process::exit(0);
            }
        }

        // And the other way round...
        let (mut read, mut write) = pipe().unwrap();

        match unsafe { unistd::fork().unwrap() } {
            unistd::ForkResult::Parent { child } => {
                drop(write);
                let mut buf = [0u8; 4];
                for n in 0..=65535u32 {
                    read.read_exact(&mut buf).unwrap();
                    assert_eq!(buf, n.to_be_bytes());
                }
                nix::sys::wait::waitpid(child, None).ok();
            }
            unistd::ForkResult::Child => {
                drop(read);
                for n in 0..=65535u32 {
                    write.write(&n.to_be_bytes()).unwrap();
                }
                process::exit(0);
            }
        }
    }

    #[test]
    fn condition() {
        let (w0, n0) = Condition::new().unwrap().split();
        let (w1, n1) = Condition::new().unwrap().split();

        match unsafe { unistd::fork().unwrap() } {
            unistd::ForkResult::Parent { .. } => {
                drop(w0);
                drop(n1);

                n0.notify();
                w1.wait();
            }
            unistd::ForkResult::Child => {
                drop(n0);
                drop(w1);

                w0.wait();
                n1.notify();
                process::exit(0);
            }
        }
    }
}
