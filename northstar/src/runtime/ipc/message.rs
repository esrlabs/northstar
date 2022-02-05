use bincode::Options;
use byteorder::{BigEndian, WriteBytesExt};
use bytes::{BufMut, BytesMut};
use lazy_static::lazy_static;
use nix::{
    cmsg_space,
    sys::socket::{self, ControlMessageOwned, SockaddrIn6},
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    io::{self, ErrorKind, IoSlice, IoSliceMut, Read, Write},
    mem::MaybeUninit,
    os::unix::prelude::{AsRawFd, FromRawFd, RawFd},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Interest},
    net::UnixStream,
};

lazy_static! {
    static ref OPTIONS: bincode::DefaultOptions = bincode::DefaultOptions::new();
}

/// Bincode encoded and length delimited message stream via Read/Write
pub struct Message<T> {
    inner: T,
}

impl<T: Write + Read + AsRawFd> Message<T> {
    /// Send bincode encoded message with a length field
    pub fn send<M: Serialize + Sync + Send>(&mut self, v: M) -> io::Result<()> {
        let size = OPTIONS
            .serialized_size(&v)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        self.inner.write_u32::<BigEndian>(size as u32)?;
        OPTIONS
            .serialize_into(&mut self.inner, &v)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))
    }

    /// Receive a bincode encoded message with a length field
    pub fn recv<M: DeserializeOwned>(&mut self) -> io::Result<Option<M>> {
        let mut buffer = [0u8; 4];
        let mut read = 0;
        while read < 4 {
            match self.inner.read(&mut buffer[read..])? {
                0 => return Ok(None),
                n => read += n,
            }
        }
        let size = u32::from_be_bytes(buffer);
        let mut buffer = vec![0; size as usize];
        self.inner.read_exact(&mut buffer)?;
        OPTIONS
            .deserialize(&buffer)
            .map(Some)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))
    }
}

impl Message<std::os::unix::net::UnixStream> {
    /// Send a file descriptor over the socket
    #[allow(unused)]
    pub fn send_fds<T: AsRawFd>(&self, fds: &[T]) -> io::Result<()> {
        let buf = &[0u8];
        let iov = &[IoSlice::new(buf)];
        let fds = fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
        let cmsg = [socket::ControlMessage::ScmRights(&fds)];
        const FLAGS: socket::MsgFlags = socket::MsgFlags::empty();

        socket::sendmsg::<SockaddrIn6>(self.inner.as_raw_fd(), iov, &cmsg, FLAGS, None)
            .map_err(os_err)
            .map(drop)
    }

    /// Receive a file descriptor via the socket
    pub fn recv_fds<T: FromRawFd, const N: usize>(&self) -> io::Result<[T; N]> {
        let mut buf = [0u8];
        let iov = &mut [IoSliceMut::new(&mut buf)];
        let mut cmsg_buffer = cmsg_space!([RawFd; N]);
        const FLAGS: socket::MsgFlags = socket::MsgFlags::empty();

        let message = socket::recvmsg::<SockaddrIn6>(
            self.inner.as_raw_fd(),
            iov,
            Some(&mut cmsg_buffer),
            FLAGS,
        )
        .map_err(os_err)?;

        recv_control_msg::<T, N>(message.cmsgs().next())
    }
}

impl AsRawFd for Message<std::os::unix::net::UnixStream> {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl<T> From<T> for Message<T>
where
    T: Read + Write,
{
    fn from(inner: T) -> Self {
        Message { inner }
    }
}

#[derive(Debug)]
pub struct AsyncMessage<T> {
    inner: T,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncMessage<T> {
    // Cancel safe send
    pub async fn send<M: Serialize + Sync + Send>(&mut self, v: M) -> io::Result<()> {
        if self.write_buffer.is_empty() {
            // Calculate the serialized message size
            let size = OPTIONS
                .serialized_size(&v)
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
            self.write_buffer.reserve(4 + size as usize);
            self.write_buffer.put_u32(size as u32);

            // Serialize the message
            let buffer = OPTIONS
                .serialize(&v)
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
            self.write_buffer.extend_from_slice(&buffer);
        }

        while !self.write_buffer.is_empty() {
            let n = self.inner.write(&self.write_buffer).await?;
            drop(self.write_buffer.split_to(n));
        }
        Ok(())
    }

    // Cancel safe recv
    pub async fn recv<'de, M: DeserializeOwned>(&mut self) -> io::Result<Option<M>> {
        while self.read_buffer.len() < 4 {
            let remaining = 4 - self.read_buffer.len();
            let mut buffer = BytesMut::with_capacity(remaining);
            match self.inner().read_buf(&mut buffer).await? {
                0 => return Ok(None),
                _ => self.read_buffer.extend_from_slice(&buffer),
            }
        }

        // Parse the message size
        let msg_len = u32::from_be_bytes(
            self.read_buffer[..4]
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid message len"))?,
        ) as usize;

        // Read until the read buffer has this length
        let target_buffer_len = msg_len as usize + 4;

        while self.read_buffer.len() < target_buffer_len {
            // Calculate how may bytes are missing to read the message
            let remaining = target_buffer_len - self.read_buffer.len();
            let mut buffer = BytesMut::with_capacity(remaining);
            match self.inner().read_buf(&mut buffer).await? {
                0 => return Ok(None),
                _ => self.read_buffer.extend_from_slice(&buffer),
            }
        }

        let message = OPTIONS
            .deserialize(&self.read_buffer[4..])
            .map(Some)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

        self.read_buffer.clear();

        Ok(message)
    }

    pub fn inner(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl AsyncMessage<tokio::net::UnixStream> {
    /// Send a file descriptor via the stream. Ensure that fd is open until this fn returns.
    pub async fn send_fds<T: AsRawFd>(&self, fds: &[T]) -> io::Result<()> {
        assert!(self.write_buffer.is_empty());

        loop {
            self.inner.writable().await?;

            match self.inner.try_io(Interest::WRITABLE, || {
                let buf = [0u8];
                let iov = &[IoSlice::new(&buf)];

                let fds = fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
                let cmsg = [socket::ControlMessage::ScmRights(&fds)];

                let flags = socket::MsgFlags::MSG_DONTWAIT;

                socket::sendmsg::<SockaddrIn6>(self.inner.as_raw_fd(), iov, &cmsg, flags, None)
                    .map_err(os_err)
            }) {
                Ok(_) => break Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => break Err(e),
            }
        }
    }

    /// Receive a file descriptor via the stream and convert it to T
    pub async fn recv_fds<T: FromRawFd, const N: usize>(&self) -> io::Result<[T; N]> {
        assert!(self.read_buffer.is_empty());

        loop {
            self.inner.readable().await?;

            let mut buf = [0u8];
            let iov = &mut [IoSliceMut::new(&mut buf)];
            let mut cmsg_buffer = cmsg_space!([RawFd; N]);
            let flags = socket::MsgFlags::MSG_DONTWAIT;

            match self.inner.try_io(Interest::READABLE, || {
                socket::recvmsg::<SockaddrIn6>(
                    self.inner.as_raw_fd(),
                    iov,
                    Some(&mut cmsg_buffer),
                    flags,
                )
                .map_err(os_err)
            }) {
                Ok(message) => break recv_control_msg::<T, N>(message.cmsgs().next()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => break Err(e),
            }
        }
    }
}

#[inline]
fn os_err(err: nix::Error) -> io::Error {
    io::Error::from_raw_os_error(err as i32)
}

impl From<UnixStream> for AsyncMessage<UnixStream> {
    fn from(inner: UnixStream) -> Self {
        Self {
            inner,
            write_buffer: BytesMut::new(),
            read_buffer: BytesMut::new(),
        }
    }
}

impl TryFrom<std::os::unix::net::UnixStream> for AsyncMessage<UnixStream> {
    type Error = io::Error;

    fn try_from(inner: std::os::unix::net::UnixStream) -> io::Result<Self> {
        inner.set_nonblocking(true)?;
        let inner = UnixStream::from_std(inner)?;
        Ok(AsyncMessage {
            inner,
            write_buffer: BytesMut::new(),
            read_buffer: BytesMut::new(),
        })
    }
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
    use std::{fs::File, io::Seek, process::exit};

    use tokio::runtime::Builder;

    use super::*;

    const ITERATIONS: usize = 10_000;

    /// Open two memfds for testing
    fn open_test_files() -> [File; 2] {
        let fd0 = nix::sys::memfd::memfd_create(
            &std::ffi::CString::new("hello").unwrap(),
            nix::sys::memfd::MemFdCreateFlag::empty(),
        )
        .unwrap();
        let fd1 = nix::sys::memfd::memfd_create(
            &std::ffi::CString::new("again").unwrap(),
            nix::sys::memfd::MemFdCreateFlag::empty(),
        )
        .unwrap();
        unsafe { [File::from_raw_fd(fd0), File::from_raw_fd(fd1)] }
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
    fn send_recv_fd_async() {
        let mut files = open_test_files();
        let mut pair = super::super::socket_pair().unwrap();

        match unsafe { nix::unistd::fork() }.unwrap() {
            nix::unistd::ForkResult::Parent { child: _ } => {
                let rt = Builder::new_current_thread().enable_all().build().unwrap();
                rt.block_on(async move {
                    let stream = AsyncMessage::try_from(pair.first()).unwrap();

                    for _ in 0..ITERATIONS {
                        stream.send_fds(&files).await.unwrap();
                        files = stream.recv_fds::<File, 2>().await.unwrap();
                    }

                    read_assert(&mut files[0], "hello");
                    read_assert(&mut files[1], "again");
                });
            }
            nix::unistd::ForkResult::Child => {
                let rt = Builder::new_current_thread().enable_all().build().unwrap();
                rt.block_on(async move {
                    let stream = AsyncMessage::try_from(pair.second()).unwrap();

                    for _ in 0..ITERATIONS {
                        let mut files = stream.recv_fds::<File, 2>().await.unwrap();
                        write_seek_flush(&mut files[0], "hello");
                        write_seek_flush(&mut files[1], "again");
                        stream.send_fds(&files).await.unwrap();
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
                let stream: Message<_> = pair.first().into();

                for _ in 0..ITERATIONS {
                    stream.send_fds(&files).unwrap();
                    files = stream.recv_fds::<File, 2>().unwrap();
                }

                read_assert(&mut files[0], "hello");
                read_assert(&mut files[1], "again");
            }
            nix::unistd::ForkResult::Child => {
                let stream: Message<_> = pair.second().into();

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
