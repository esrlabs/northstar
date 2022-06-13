use std::{io, os::unix::net::UnixStream};

/// Create a connected pair of unix sockets.
pub fn socket_pair() -> io::Result<SocketPair> {
    let (first, second) = UnixStream::pair()?;

    Ok(SocketPair {
        first: Some(first),
        second: Some(second),
    })
}

#[derive(Debug)]
pub struct SocketPair {
    first: Option<UnixStream>,
    second: Option<UnixStream>,
}

impl SocketPair {
    pub fn first(&mut self) -> UnixStream {
        self.second.take().expect("double take");
        self.first.take().expect("double take")
    }

    pub fn second(&mut self) -> UnixStream {
        self.first.take().expect("double take");
        self.second.take().expect("double take")
    }
}
