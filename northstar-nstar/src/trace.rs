use std::{
    io::{self, Write},
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    /// Trace every byte read and written to stoud
    pub struct Trace<T, IO> {
        #[pin]
        inner: T,
        io: IO,
    }
}

impl<T, IO> Trace<T, IO> {
    pub fn new(inner: T, io: IO) -> Self {
        Self { inner, io }
    }
}

impl<T: AsyncRead + Unpin, IO: Write> AsyncRead for Trace<T, IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut project = self.project();
        let result = project.inner.poll_read(cx, buf);
        io::copy(&mut buf.filled(), &mut project.io)?;
        result
    }
}

impl<T: AsyncWrite + Unpin, IO> AsyncWrite for Trace<T, IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        io::copy(&mut io::Cursor::new(buf), &mut io::stdout())?;
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }
}
