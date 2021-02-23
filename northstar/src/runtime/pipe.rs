// Copyright (c) 2019 - 2020 ESRLabs
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

use nix::{fcntl, fcntl::OFlag, unistd};
use std::{
    convert::TryFrom,
    io,
    os::unix::io::{AsRawFd, RawFd},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{unix::AsyncFd, AsyncRead, AsyncWrite, ReadBuf};

/// Opens a pipe(2) with both ends blocking
pub(crate) fn pipe() -> io::Result<(PipeReader, PipeWriter)> {
    let (readfd, writefd) = unistd::pipe().map_err(from_nix)?;
    Ok((PipeReader(readfd), PipeWriter(writefd)))
}

/// Read end of a pipe(2)
#[derive(Debug)]
pub(crate) struct PipeReader(RawFd);

impl std::io::Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unistd::read(self.0, buf).map_err(from_nix)
    }
}

impl AsRawFd for PipeReader {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        unistd::close(self.0).unwrap();
    }
}

/// Write end of a pipe(2)
#[derive(Debug)]
pub(crate) struct PipeWriter(RawFd);

impl std::io::Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unistd::write(self.0, buf).map_err(from_nix)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsRawFd for PipeWriter {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        unistd::close(self.0).unwrap();
    }
}

/// Pipe's synchronous reading end
#[derive(Debug)]
pub(crate) struct AsyncPipeReader(AsyncFd<PipeReader>);

impl TryFrom<PipeReader> for AsyncPipeReader {
    type Error = io::Error;

    fn try_from(reader: PipeReader) -> Result<Self, Self::Error> {
        let fd = reader.as_raw_fd();
        set_nonblocking(fd)?;
        Ok(AsyncPipeReader(AsyncFd::new(reader)?))
    }
}

impl AsyncRead for AsyncPipeReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = futures::ready!(self.0.poll_read_ready(cx))?;
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

/// Pipe's synchronous writing end
#[derive(Debug)]
pub(crate) struct AsyncPipeWriter(AsyncFd<PipeWriter>);

impl TryFrom<PipeWriter> for AsyncPipeWriter {
    type Error = io::Error;

    fn try_from(writer: PipeWriter) -> Result<Self, Self::Error> {
        let fd = writer.as_raw_fd();
        set_nonblocking(fd)?;
        Ok(AsyncPipeWriter(AsyncFd::new(writer)?))
    }
}

impl AsyncWrite for AsyncPipeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = futures::ready!(self.0.poll_write_ready(cx))?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // map nix::Error to io::Error
                match unistd::write(fd, buf) {
                    Ok(n) => Ok(n),
                    // read(2) on a nonblocking file (O_NONBLOCK) returns EAGAIN or EWOULDBLOCK in
                    // case that the read would block. That case is handled by `try_io`.
                    Err(e) => Err(from_nix(e)),
                }
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Sets O_NONBLOCK flag for the input file descriptor
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let mut flags = fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFL)
        .map(OFlag::from_bits)
        .map_err(from_nix)?
        .unwrap();
    flags |= OFlag::O_NONBLOCK;
    fcntl::fcntl(fd, fcntl::FcntlArg::F_SETFL(flags)).map_err(from_nix)?;
    Ok(())
}

/// Maps an nix::Error to a io::Error
fn from_nix(error: nix::Error) -> io::Error {
    match error {
        nix::Error::Sys(e) => io::Error::from_raw_os_error(e as i32),
        e => io::Error::new(io::ErrorKind::Other, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        convert::TryInto,
        io::{Read, Write},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test() {
        let (mut r, mut w) = pipe().unwrap();

        w.write(b"Hello").unwrap();

        let mut buf = [0u8; 5];
        r.read_exact(&mut buf).unwrap();

        assert_eq!(&buf, b"Hello");
    }

    #[test]
    fn read_write() {
        let (mut r, mut w) = pipe().unwrap();

        let w_task = std::thread::spawn(move || {
            for n in 0..=65535u32 {
                w.write(&n.to_be_bytes()).unwrap();
            }
        });

        let r_task = std::thread::spawn(move || {
            let mut buf = [0u8; 4];
            for n in 0..=65535u32 {
                r.read_exact(&mut buf).unwrap();
                assert_eq!(buf, n.to_be_bytes());
            }
        });

        w_task.join().unwrap();
        r_task.join().unwrap();
    }

    #[tokio::test]
    async fn async_read_write() {
        let (r, w) = pipe().unwrap();

        let mut async_reader: AsyncPipeReader = r.try_into().unwrap();
        let mut async_writer: AsyncPipeWriter = w.try_into().unwrap();

        let w_task = tokio::spawn(async move {
            for n in 0..=65535u32 {
                async_writer.write(&n.to_be_bytes()).await.unwrap();
            }
        });

        let r_task = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            for n in 0..=65535u32 {
                async_reader.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, n.to_be_bytes());
            }
        });
        tokio::try_join!(w_task, r_task).unwrap();
    }
}
