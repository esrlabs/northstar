use bincode::Options;
use byteorder::{BigEndian, WriteBytesExt};
use bytes::{BufMut, BytesMut};
use lazy_static::lazy_static;
use nix::{
    cmsg_space,
    sys::{
        socket::{self, ControlMessageOwned},
        uio,
    },
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    io::{self, ErrorKind, Read, Write},
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
        let iov = &[uio::IoVec::from_slice(buf)];
        let fds = fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
        let cmsg = [socket::ControlMessage::ScmRights(&fds)];
        const FLAGS: socket::MsgFlags = socket::MsgFlags::empty();

        socket::sendmsg(self.inner.as_raw_fd(), iov, &cmsg, FLAGS, None)
            .map_err(os_err)
            .map(drop)
    }

    /// Receive a file descriptor via the socket
    pub fn recv_fds<T: FromRawFd, const N: usize>(&self) -> io::Result<[T; N]> {
        let mut buf = [0u8];
        let iov = &[uio::IoVec::from_mut_slice(&mut buf)];
        let mut cmsg_buffer = cmsg_space!([RawFd; N]);
        const FLAGS: socket::MsgFlags = socket::MsgFlags::empty();

        let message = socket::recvmsg(self.inner.as_raw_fd(), iov, Some(&mut cmsg_buffer), FLAGS)
            .map_err(os_err)?;

        recv_control_msg::<T, N>(message.cmsgs().next())
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
        let msg_len = u32::from_be_bytes(self.read_buffer[..4].try_into().unwrap()) as usize;

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
                let iov = &[uio::IoVec::from_slice(&buf)];

                let fds = fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
                let cmsg = [socket::ControlMessage::ScmRights(&fds)];

                let flags = socket::MsgFlags::MSG_DONTWAIT;

                socket::sendmsg(self.inner.as_raw_fd(), iov, &cmsg, flags, None).map_err(os_err)
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
            let iov = &[uio::IoVec::from_mut_slice(&mut buf)];
            let mut cmsg_buffer = cmsg_space!([RawFd; N]);
            let flags = socket::MsgFlags::MSG_DONTWAIT;

            match self.inner.try_io(Interest::READABLE, || {
                socket::recvmsg(self.inner.as_raw_fd(), iov, Some(&mut cmsg_buffer), flags)
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
                "Failed to receive fd: unexpected control message: {:?}",
                message
            ),
        )),
        None => Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Failed to receive fd: missing control message: {:?}",
                message
            ),
        )),
    }
}

#[cfg(test)]
mod test {
    use std::{io::Seek, process::exit};

    use nix::unistd::close;
    use tokio::{io::AsyncSeekExt, runtime::Builder};

    use super::*;

    #[test]
    fn send_recv_fd_async() {
        let mut fd0 = nix::sys::memfd::memfd_create(
            &std::ffi::CString::new("hello").unwrap(),
            nix::sys::memfd::MemFdCreateFlag::empty(),
        )
        .unwrap();
        let mut fd1 = nix::sys::memfd::memfd_create(
            &std::ffi::CString::new("again").unwrap(),
            nix::sys::memfd::MemFdCreateFlag::empty(),
        )
        .unwrap();

        let mut pair = super::super::socket_pair().unwrap();

        const ITERATONS: usize = 100_000;

        match unsafe { nix::unistd::fork() }.unwrap() {
            nix::unistd::ForkResult::Parent { child: _ } => {
                let parent = pair.first();
                let rt = Builder::new_current_thread().enable_all().build().unwrap();
                rt.block_on(async move {
                    let stream = AsyncMessage::try_from(parent).unwrap();

                    // Send and receive the fds a couple of times
                    for _ in 0..ITERATONS {
                        stream.send_fds(&[fd0, fd1]).await.unwrap();
                        close(fd0).unwrap();
                        close(fd1).unwrap();

                        let fds = stream.recv_fds::<RawFd, 2>().await.unwrap();
                        fd0 = fds[0];
                        fd1 = fds[1];
                    }

                    // Done - check fd content

                    let mut buf = String::new();
                    let mut file0 = unsafe { tokio::fs::File::from_raw_fd(fd0) };
                    file0.seek(io::SeekFrom::Start(0)).await.unwrap();
                    file0.read_to_string(&mut buf).await.unwrap();
                    assert_eq!(buf, "hello");

                    let mut buf = String::new();
                    let mut file1 = unsafe { tokio::fs::File::from_raw_fd(fd1) };
                    file1.seek(io::SeekFrom::Start(0)).await.unwrap();
                    file1.read_to_string(&mut buf).await.unwrap();
                    assert_eq!(buf, "again");
                });
            }
            nix::unistd::ForkResult::Child => {
                let child = pair.second();
                let rt = Builder::new_current_thread().enable_all().build().unwrap();
                rt.block_on(async move {
                    let stream = AsyncMessage::try_from(child).unwrap();

                    // Send and receive the fds a couple of times
                    for _ in 0..ITERATONS {
                        let mut files = stream.recv_fds::<tokio::fs::File, 2>().await.unwrap();

                        files[0].seek(io::SeekFrom::Start(0)).await.unwrap();
                        files[0].write_all(b"hello").await.unwrap();
                        files[0].flush().await.unwrap();

                        files[1].seek(io::SeekFrom::Start(0)).await.unwrap();
                        files[1].write_all(b"again").await.unwrap();
                        files[1].flush().await.unwrap();

                        // Send it back
                        stream.send_fds(&files).await.unwrap();
                    }
                });
                exit(0);
            }
        }
    }

    #[test]
    fn send_recv_fd_blocking() {
        let mut fd = nix::sys::memfd::memfd_create(
            &std::ffi::CString::new("foo").unwrap(),
            nix::sys::memfd::MemFdCreateFlag::empty(),
        )
        .unwrap();

        let mut pair = super::super::socket_pair().unwrap();

        const ITERATONS: usize = 100_000;

        match unsafe { nix::unistd::fork() }.unwrap() {
            nix::unistd::ForkResult::Parent { child: _ } => {
                let parent = pair.first();
                let stream = Message::try_from(parent).unwrap();
                for _ in 0..ITERATONS {
                    stream.send_fds(&[fd]).unwrap();
                    close(fd).unwrap();
                    fd = stream.recv_fds::<RawFd, 1>().unwrap()[0];
                }

                // Done - check fd content
                let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
                file.seek(io::SeekFrom::Start(0)).unwrap();
                let mut buf = String::new();
                file.read_to_string(&mut buf).unwrap();
                assert_eq!(buf, "hello");
            }
            nix::unistd::ForkResult::Child => {
                let child = pair.second();
                let mut stream = Message::try_from(child).unwrap();
                for _ in 0..ITERATONS {
                    let mut file = stream.recv_fds::<std::fs::File, 1>().unwrap();

                    // Write some bytes in to the fd
                    file[0].seek(io::SeekFrom::Start(0)).unwrap();
                    file[0].write_all(b"hello").unwrap();
                    file[0].flush().unwrap();

                    // Send it back
                    stream.send_fds(&[file[0].as_raw_fd()]).unwrap();
                    drop(file);
                }
                stream.recv::<i32>().ok();
                exit(0);
            }
        }
    }
}
