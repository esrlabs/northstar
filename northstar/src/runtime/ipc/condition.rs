use std::{
    io::Result,
    os::unix::prelude::{AsRawFd, IntoRawFd, RawFd},
};

use tokio::io::AsyncReadExt;

use super::{
    pipe::{pipe, AsyncPipeRead, PipeRead, PipeWrite},
    raw_fd_ext::RawFdExt,
};

#[allow(unused)]
#[derive(Debug)]
pub struct Condition {
    read: PipeRead,
    write: PipeWrite,
}

#[allow(unused)]
impl Condition {
    pub fn new() -> Result<Condition> {
        let (rfd, wfd) = pipe()?;

        Ok(Condition {
            read: rfd,
            write: wfd,
        })
    }

    pub fn set_cloexec(&self) {
        self.read.set_cloexec(true);
        self.write.set_cloexec(true);
    }

    pub fn wait(mut self) {
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

    pub fn notify(self) {}

    pub fn split(self) -> (ConditionWait, ConditionNotify) {
        (
            ConditionWait { read: self.read },
            ConditionNotify { write: self.write },
        )
    }
}

#[derive(Debug)]
pub struct ConditionWait {
    read: PipeRead,
}

impl ConditionWait {
    #[allow(unused)]
    pub fn wait(mut self) {
        use std::io::Read;
        loop {
            match self.read.read(&mut [0u8; 1]) {
                Ok(n) if n == 0 => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }

    pub async fn async_wait(self) {
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

#[derive(Debug)]
pub struct ConditionNotify {
    write: PipeWrite,
}

impl ConditionNotify {
    #[allow(unused)]
    pub fn notify(self) {
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
    use nix::unistd;

    use super::*;

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
                std::process::exit(0);
            }
        }
    }
}
