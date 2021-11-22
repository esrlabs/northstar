use std::{
    io::{ErrorKind, Read, Write},
    os::unix::prelude::{AsRawFd, RawFd},
};

use bincode::Options;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::AsyncReadExt;

use super::pipe::{pipe, AsyncPipeRead, PipeRead, PipeWrite};

/// Wrap a pipe to transfer bincoded structs that implement `Serialize` and `Deserialize`
pub struct Channel {
    tx: PipeWrite,
    rx: std::io::BufReader<PipeRead>,
}

impl Channel {
    /// Create a new pipe channel
    pub fn new() -> Channel {
        let (rx, tx) = pipe().expect("Failed to create pipe");
        Channel {
            tx,
            rx: std::io::BufReader::new(rx),
        }
    }

    /// Raw fds for the rx and tx pipe
    pub fn as_raw_fd(&self) -> (RawFd, RawFd) {
        (self.tx.as_raw_fd(), self.rx.get_ref().as_raw_fd())
    }
}

impl Channel {
    /// Drops the tx part and returns a AsyncChannelRead
    pub fn into_async_read(self) -> AsyncChannelRead {
        let rx = self
            .rx
            .into_inner()
            .try_into()
            .expect("Failed to convert pipe read");
        AsyncChannelRead {
            rx: tokio::io::BufReader::new(rx),
        }
    }

    /// Send v bincode serialized
    pub fn send<T: Serialize>(&mut self, v: &T) -> std::io::Result<()> {
        let buffer = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(v)
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e))?;
        self.tx.write_u32::<BigEndian>(buffer.len() as u32)?;
        self.tx.write_all(&buffer)
    }

    /// Receive bincode serialized
    #[allow(unused)]
    pub fn recv<T>(&mut self) -> std::io::Result<T>
    where
        T: DeserializeOwned,
    {
        let size = self.rx.read_u32::<BigEndian>()?;
        let mut buffer = vec![0; size as usize];
        self.rx.read_exact(&mut buffer)?;
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .deserialize(&buffer)
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e))
    }
}

/// Async version of Channel
pub struct AsyncChannelRead {
    rx: tokio::io::BufReader<AsyncPipeRead>,
}

impl AsyncChannelRead {
    pub async fn recv<'de, T>(&mut self) -> std::io::Result<T>
    where
        T: DeserializeOwned,
    {
        let size = self.rx.read_u32().await?;
        let mut buffer = vec![0; size as usize];
        self.rx.read_exact(&mut buffer).await?;
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .deserialize(&buffer)
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e))
    }
}

#[cfg(test)]
mod tests {
    use nix::{sys::wait, unistd};

    use super::*;
    use crate::runtime::ExitStatus;

    #[tokio::test(flavor = "current_thread")]
    async fn channel_async() {
        let mut channel = Channel::new();

        for i in 0..=255 {
            channel.send(&std::time::Duration::from_secs(1)).unwrap();
            channel.send(&ExitStatus::Exit(i)).unwrap();
            channel.send(&ExitStatus::Signalled(10)).unwrap();
        }

        for i in 0..=255 {
            assert_eq!(
                channel.recv::<std::time::Duration>().unwrap(),
                std::time::Duration::from_secs(1)
            );
            assert_eq!(channel.recv::<ExitStatus>().unwrap(), ExitStatus::Exit(i));
            assert_eq!(
                channel.recv::<ExitStatus>().unwrap(),
                ExitStatus::Signalled(10)
            );
        }

        for i in 0..=255 {
            channel.send(&std::time::Duration::from_secs(1)).unwrap();
            channel.send(&ExitStatus::Exit(i)).unwrap();
            channel.send(&ExitStatus::Signalled(10)).unwrap();
        }

        let mut channel = channel.into_async_read();
        for i in 0..=255 {
            assert_eq!(
                channel.recv::<std::time::Duration>().await.unwrap(),
                std::time::Duration::from_secs(1)
            );
            assert_eq!(
                channel.recv::<ExitStatus>().await.unwrap(),
                ExitStatus::Exit(i)
            );
            assert_eq!(
                channel.recv::<ExitStatus>().await.unwrap(),
                ExitStatus::Signalled(10)
            );
        }
    }

    #[test]
    fn channel_fork() {
        let mut channel = Channel::new();

        match unsafe { unistd::fork().expect("Failed to fork") } {
            unistd::ForkResult::Parent { child } => {
                wait::waitpid(Some(child), None).expect("Failed to waitpid");
                for i in 0..=255i32 {
                    assert_eq!(
                        channel.recv::<std::time::Duration>().unwrap(),
                        std::time::Duration::from_secs(i as u64)
                    );
                    assert_eq!(channel.recv::<ExitStatus>().unwrap(), ExitStatus::Exit(i));
                    assert_eq!(
                        channel.recv::<ExitStatus>().unwrap(),
                        ExitStatus::Signalled(10)
                    );
                }
            }
            unistd::ForkResult::Child => {
                for i in 0..=255i32 {
                    channel
                        .send(&std::time::Duration::from_secs(i as u64))
                        .unwrap();
                    channel.send(&ExitStatus::Exit(i)).unwrap();
                    channel.send(&ExitStatus::Signalled(10)).unwrap();
                }
                std::process::exit(0);
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn channel_fork_close() {
        let channel = Channel::new();
        match unsafe { unistd::fork().expect("Failed to fork") } {
            unistd::ForkResult::Parent { child } => {
                let mut channel = channel.into_async_read();
                wait::waitpid(Some(child), None).expect("Failed to waitpid");
                assert!(channel.recv::<ExitStatus>().await.is_err());
            }
            unistd::ForkResult::Child => {
                drop(channel);
                std::process::exit(0);
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn channel_close() {
        let channel = Channel::new();
        // Converting into a AsyncChannelRead closes the sending part
        let mut channel = channel.into_async_read();
        assert!(channel.recv::<ExitStatus>().await.is_err());
    }
}
