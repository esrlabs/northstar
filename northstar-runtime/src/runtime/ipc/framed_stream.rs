use bincode::{DefaultOptions, Options};
use byteorder::{BigEndian, WriteBytesExt};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use nix::{
    cmsg_space,
    sys::socket::{self, ControlMessageOwned, SockaddrIn6},
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    io::{self, ErrorKind, IoSlice, IoSliceMut, Read},
    mem::MaybeUninit,
    os::unix::prelude::{AsRawFd, FromRawFd, RawFd},
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Bincode encoded and length delimited message stream via Read/Write
#[derive(Debug)]
pub struct FramedUnixStream(std::os::unix::net::UnixStream);

impl FramedUnixStream {
    pub fn new(inner: std::os::unix::net::UnixStream) -> Self {
        Self(inner)
    }

    /// Send bincode encoded message with a length field
    pub fn send<M: Serialize + Sync + Send>(&mut self, v: M) -> io::Result<()> {
        let size = DefaultOptions::default()
            .serialized_size(&v)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        self.0.write_u32::<BigEndian>(size as u32)?;
        DefaultOptions::default()
            .serialize_into(&mut self.0, &v)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))
    }

    /// Receive a bincode encoded message with a length field
    pub fn recv<M: DeserializeOwned>(&mut self) -> io::Result<Option<M>> {
        // Discard the size
        self.0.read_exact(&mut [0u8; 4])?;
        DefaultOptions::default()
            .deserialize_from(&self.0)
            .map(Some)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))
    }

    /// Send file descriptors over the unix socket connection
    #[allow(unused)]
    pub fn send_fds<T: AsRawFd>(&self, fds: &[T]) -> io::Result<()> {
        let buf = &[0u8];
        let iov = &[IoSlice::new(buf)];
        let fds = fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
        let cmsg = [socket::ControlMessage::ScmRights(&fds)];
        const FLAGS: socket::MsgFlags = socket::MsgFlags::empty();

        socket::sendmsg::<SockaddrIn6>(self.0.as_raw_fd(), iov, &cmsg, FLAGS, None)
            .map_err(os_err)
            .map(drop)
    }

    /// Receive a file descriptor via the socket
    pub fn recv_fds<T: FromRawFd, const N: usize>(&self) -> io::Result<[T; N]> {
        let mut buf = [0u8];
        let iov = &mut [IoSliceMut::new(&mut buf)];
        let mut cmsg_buffer = cmsg_space!([RawFd; N]);
        const FLAGS: socket::MsgFlags = socket::MsgFlags::empty();

        let message =
            socket::recvmsg::<SockaddrIn6>(self.0.as_raw_fd(), iov, Some(&mut cmsg_buffer), FLAGS)
                .map_err(os_err)?;

        recv_control_msg::<T, N>(message.cmsgs().next())
    }

    /// Into UnixStream
    pub fn into_inner(self) -> std::os::unix::net::UnixStream {
        self.0
    }
}

#[derive(Debug)]
pub struct AsyncFramedUnixStream(Framed<tokio::net::UnixStream, LengthDelimitedCodec>);

impl AsyncFramedUnixStream {
    pub fn new(inner: std::os::unix::net::UnixStream) -> Self {
        inner
            .set_nonblocking(true)
            .expect("failed to set nonblocking");
        let inner =
            tokio::net::UnixStream::from_std(inner).expect("failed to convert tokio stream");
        let framed = LengthDelimitedCodec::builder()
            .length_field_length(4)
            .big_endian()
            .new_framed(inner);
        Self(framed)
    }

    // Cancel safe send
    pub async fn send<M: Serialize + Sync + Send>(&mut self, v: M) -> io::Result<()> {
        let data = DefaultOptions::default()
            .serialize(&v)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        let data = Bytes::from(data);
        self.0.send(data).await?;
        Ok(())
    }

    // Cancel safe recv
    pub async fn recv<'de, M: DeserializeOwned>(&mut self) -> io::Result<Option<M>> {
        let buffer = self
            .0
            .next()
            .await
            .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "unexpected EOF"))??;
        DefaultOptions::default()
            .deserialize(&buffer)
            .map(Some)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))
    }
}

#[inline]
fn os_err(err: nix::Error) -> io::Error {
    io::Error::from_raw_os_error(err as i32)
}

fn recv_control_msg<T: FromRawFd, const N: usize>(
    message: Option<ControlMessageOwned>,
) -> io::Result<[T; N]> {
    match message {
        Some(socket::ControlMessageOwned::ScmRights(fds)) => {
            let mut result: [MaybeUninit<T>; N] = unsafe { MaybeUninit::uninit().assume_init() };

            for (fd, result) in fds.iter().zip(&mut result) {
                result.write(unsafe { T::from_raw_fd(*fd) });
            }

            let ptr = &mut result as *mut _ as *mut [T; N];
            let res = unsafe { ptr.read() };
            core::mem::forget(result);
            Ok(res)
        }
        Some(message) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "failed to receive fd: unexpected control message: {:?}",
                message
            ),
        )),
        None => Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "failed to receive fd: missing control message: {:?}",
                message
            ),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::{
        fs::File,
        io::{Seek, Write},
        process::exit,
    };

    use super::*;

    const ITERATIONS: usize = 10_000;

    /// Open two memfds for testing
    fn open_test_files() -> [File; 2] {
        let opts = memfd::MemfdOptions::default();
        let file0 = opts.create("hello").unwrap().into_file();
        let file1 = opts.create("again").unwrap().into_file();
        [file0, file1]
    }

    /// Read file to end and assert the result is equal to the expected `s`
    fn read_assert(file: &mut File, s: &str) {
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        write_seek_flush(file, "");
        assert_eq!(buf, s);
    }

    /// Write `s` to file and seek to the beginning
    fn write_seek_flush(file: &mut File, s: &str) {
        file.write_all(s.as_bytes()).unwrap();
        file.seek(io::SeekFrom::Start(0)).unwrap();
        file.flush().unwrap();
    }

    #[test]
    fn send_recv_sync() {
        let mut pair = super::super::socket_pair().unwrap();

        match unsafe { nix::unistd::fork() }.unwrap() {
            nix::unistd::ForkResult::Parent { child: _ } => {
                let mut stream = FramedUnixStream::new(pair.first());
                for _ in 0..ITERATIONS {
                    let tx = nanoid::nanoid!();
                    stream.send(&tx).unwrap();
                    let rx = stream.recv::<String>().unwrap().unwrap();
                    assert_eq!(tx, rx);
                }
            }
            nix::unistd::ForkResult::Child => {
                let mut stream = FramedUnixStream::new(pair.second());
                while let Ok(Some(s)) = stream.recv::<String>() {
                    stream.send(s).unwrap();
                }
                exit(0);
            }
        }
    }

    #[test]
    fn send_recv_async() {
        let mut pair = super::super::socket_pair().unwrap();

        match unsafe { nix::unistd::fork() }.unwrap() {
            nix::unistd::ForkResult::Parent { child: _ } => {
                tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .build()
                    .unwrap()
                    .block_on(async move {
                        let mut stream = AsyncFramedUnixStream::new(pair.first());
                        for _ in 0..ITERATIONS {
                            let tx = nanoid::nanoid!();
                            stream.send(&tx).await.unwrap();
                            let rx = stream.recv::<String>().await.unwrap().unwrap();
                            assert_eq!(tx, rx);
                        }
                    });

                exit(0);
            }
            nix::unistd::ForkResult::Child => {
                tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .build()
                    .unwrap()
                    .block_on(async move {
                        let mut stream = AsyncFramedUnixStream::new(pair.second());
                        while let Ok(Some(s)) = stream.recv::<String>().await {
                            stream.send(s).await.unwrap();
                        }
                    });

                exit(0);
            }
        }
    }

    #[test]
    fn send_recv_fd_blocking() {
        let mut files = open_test_files();
        let mut pair = super::super::socket_pair().unwrap();

        match unsafe { nix::unistd::fork() }.unwrap() {
            nix::unistd::ForkResult::Parent { child: _ } => {
                let stream = FramedUnixStream::new(pair.first());

                for _ in 0..ITERATIONS {
                    stream.send_fds(&files).unwrap();
                    files = stream.recv_fds::<File, 2>().unwrap();
                }

                read_assert(&mut files[0], "hello");
                read_assert(&mut files[1], "again");
            }
            nix::unistd::ForkResult::Child => {
                let stream = FramedUnixStream::new(pair.second());

                for _ in 0..ITERATIONS {
                    let mut files = stream.recv_fds::<File, 2>().unwrap();
                    write_seek_flush(&mut files[0], "hello");
                    write_seek_flush(&mut files[1], "again");
                    stream.send_fds(&files).unwrap();
                }
                exit(0);
            }
        }
    }
}
