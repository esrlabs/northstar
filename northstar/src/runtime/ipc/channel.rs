use std::{
    io::{Read, Write},
    os::unix::prelude::{AsRawFd, RawFd},
};

use bincode::Options;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::pipe::{pipe, AsyncPipeRead, AsyncPipeWrite, PipeRead, PipeWrite};

/// [`PipeWrite`] wrapper for sending serializable data
pub struct Sender<S> {
    pipe: PipeWrite,
    _marker: std::marker::PhantomData<S>,
}

impl<S> Sender<S>
where
    S: Serialize + DeserializeOwned,
{
    /// Send bincode serialized
    pub fn send(&mut self, s: S) -> std::io::Result<()> {
        let buffer = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&s)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        self.pipe.write_u32::<BigEndian>(buffer.len() as u32)?;
        self.pipe.write_all(&buffer)
    }
}

impl<S> AsRawFd for Sender<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.pipe.as_raw_fd()
    }
}

impl<S> From<PipeWrite> for Sender<S>
where
    S: Serialize + DeserializeOwned,
{
    fn from(pipe: PipeWrite) -> Self {
        Sender {
            pipe,
            _marker: std::marker::PhantomData,
        }
    }
}

/// [`PipeRead`] wrapper for receiving serializable data
pub struct Receiver<S> {
    pipe: std::io::BufReader<PipeRead>,
    _marker: std::marker::PhantomData<S>,
}

impl<S> Receiver<S>
where
    S: Serialize + DeserializeOwned,
{
    /// Receive bincode serialized
    pub fn recv(&mut self) -> std::io::Result<S> {
        let size = self.pipe.read_u32::<BigEndian>()?;
        let mut buffer = vec![0; size as usize];
        self.pipe.read_exact(&mut buffer)?;
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .deserialize(&buffer)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

impl<S> AsRawFd for Receiver<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.pipe.get_ref().as_raw_fd()
    }
}

impl<S> From<PipeRead> for Receiver<S>
where
    S: Serialize + DeserializeOwned,
{
    fn from(pipe: PipeRead) -> Self {
        Receiver {
            pipe: std::io::BufReader::new(pipe),
            _marker: std::marker::PhantomData,
        }
    }
}

/// Interprocess Channel
///
/// # Usage
///
/// This type must be created before calling `fork` and then each of the resulting processes call
/// the corresponding `read_end()` or `write_end()` to get the receiving and sending ends
/// correspondingly.
///
/// Note that these functions do not drop the builder after being called. Unfortunately we are kind
/// of forced to use a mutable reference instead to trick the borrow checker when these functions
/// are called from both sides of `fork`.
///
pub struct Channel<S> {
    rx: Option<PipeRead>,
    tx: Option<PipeWrite>,
    phantom: std::marker::PhantomData<S>,
}

impl<S> Channel<S>
where
    S: Serialize + DeserializeOwned,
{
    pub fn new() -> Self {
        let (rx, tx) = pipe().expect("Failed to create pipe");
        Channel {
            rx: Some(rx),
            tx: Some(tx),
            phantom: std::marker::PhantomData,
        }
    }

    pub fn read_end(&mut self) -> Receiver<S> {
        let rx = self
            .rx
            .take()
            .expect("ChannelBuilder::read_end called twice or called together with ChannelBuilder::write_end");

        // drop the writing end
        self.tx.take();

        Receiver {
            pipe: std::io::BufReader::new(rx),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn write_end(&mut self) -> Sender<S> {
        let tx = self
            .tx
            .take()
            .expect("ChannelBuilder::write_end called twice or called together with ChannelBuilder::read_end");

        // drop the reading end
        self.rx.take();

        Sender {
            pipe: tx,
            _marker: std::marker::PhantomData,
        }
    }
}

/// Asynchronous [`Sender`]
pub struct AsyncSender<S> {
    pipe: AsyncPipeWrite,
    _marker: std::marker::PhantomData<S>,
}

impl<S> AsyncSender<S>
where
    S: Serialize + DeserializeOwned,
{
    pub async fn send(&mut self, s: S) -> std::io::Result<()> {
        let buffer = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&s)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        self.pipe.write_u32(buffer.len() as u32).await?;
        self.pipe.write_all(&buffer).await
    }
}

impl<S> From<Sender<S>> for AsyncSender<S>
where
    S: Serialize + DeserializeOwned,
{
    fn from(s: Sender<S>) -> Self {
        AsyncSender {
            pipe: s.pipe.try_into().unwrap(),
            _marker: std::marker::PhantomData,
        }
    }
}

/// Asynchronous [`Receiver`]
pub struct AsyncReceiver<S> {
    pipe: tokio::io::BufReader<AsyncPipeRead>,
    _marker: std::marker::PhantomData<S>,
}

impl<S> AsyncReceiver<S>
where
    S: Serialize + DeserializeOwned,
{
    pub async fn recv(&mut self) -> std::io::Result<S> {
        let size = self.pipe.read_u32().await?;
        let mut buffer = vec![0; size as usize];
        self.pipe.read_exact(&mut buffer).await?;
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .deserialize(&buffer)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

impl<S> From<Receiver<S>> for AsyncReceiver<S>
where
    S: Serialize + DeserializeOwned,
{
    fn from(r: Receiver<S>) -> Self {
        AsyncReceiver {
            pipe: tokio::io::BufReader::new(r.pipe.into_inner().try_into().unwrap()),
            _marker: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use nix::{sys::wait, unistd};

    use super::*;
    use crate::runtime::ExitStatus;

    #[tokio::test(flavor = "current_thread")]
    async fn channel_async() {
        let (rx, tx) = pipe().expect("Failed to create pipe");
        let sender: Sender<ExitStatus> = tx.into();
        let receiver: Receiver<ExitStatus> = rx.into();

        let mut sender: AsyncSender<_> = sender.into();
        for i in 0..=255 {
            sender.send(ExitStatus::Exit(i)).await.unwrap();
            sender.send(ExitStatus::Signalled(10)).await.unwrap();
        }

        let mut receiver: AsyncReceiver<_> = receiver.into();
        for i in 0..=255 {
            assert_eq!(receiver.recv().await.unwrap(), ExitStatus::Exit(i));
            assert_eq!(receiver.recv().await.unwrap(), ExitStatus::Signalled(10));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn channel_fork() {
        let mut builder = Channel::<ExitStatus>::new();

        match unsafe { unistd::fork().expect("Failed to fork") } {
            unistd::ForkResult::Parent { child } => {
                let mut channel: AsyncReceiver<_> = builder.read_end().into();
                wait::waitpid(Some(child), None).expect("Failed to waitpid");
                for i in 0..=255i32 {
                    assert_eq!(channel.recv().await.unwrap(), ExitStatus::Exit(i));
                    assert_eq!(channel.recv().await.unwrap(), ExitStatus::Signalled(10));
                }
            }
            unistd::ForkResult::Child => {
                let mut channel: AsyncSender<_> = builder.write_end().into();
                for i in 0..=255i32 {
                    channel.send(ExitStatus::Exit(i)).await.unwrap();
                    channel.send(ExitStatus::Signalled(10)).await.unwrap();
                }
                std::process::exit(0);
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn channel_fork_close() {
        let mut builder = Channel::<ExitStatus>::new();
        match unsafe { unistd::fork().expect("Failed to fork") } {
            unistd::ForkResult::Parent { child } => {
                let mut receiver: AsyncReceiver<_> = builder.read_end().into();
                wait::waitpid(Some(child), None).expect("Failed to waitpid");
                assert!(receiver.recv().await.is_err());
            }
            unistd::ForkResult::Child => {
                let sender = builder.write_end();
                drop(sender);
                std::process::exit(0);
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn channel_close() {
        let mut receiver = Channel::<ExitStatus>::new().read_end();
        // Converting into a AsyncChannelRead closes the sending part
        assert!(receiver.recv().is_err());
    }
}
