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
        let filled_pre_read = buf.filled().len();
        match project.inner.poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                io::copy(
                    &mut io::Cursor::new(&buf.filled()[filled_pre_read..]),
                    &mut project.io,
                )?;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncWrite + Unpin, IO> AsyncWrite for Trace<T, IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.project().inner.poll_write(cx, buf) {
            Poll::Ready(Ok(n)) if n > 0 => {
                io::copy(&mut io::Cursor::new(&buf[..n]), &mut io::stdout())?;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(e) => Poll::Ready(e),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }
}
