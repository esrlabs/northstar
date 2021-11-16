use std::os::unix::net::UnixStream;

use tokio::net::UnixStream as TokioUnixStream;

pub fn socket_pair() -> std::io::Result<SocketPair> {
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
        self.second.take().unwrap();
        self.first.take().unwrap()
    }

    pub fn second(&mut self) -> UnixStream {
        self.first.take().unwrap();
        self.second.take().unwrap()
    }

    pub fn first_async(&mut self) -> std::io::Result<TokioUnixStream> {
        let socket = self.first();
        socket.set_nonblocking(true)?;
        TokioUnixStream::from_std(socket)
    }

    #[allow(dead_code)]
    pub fn second_async(&mut self) -> std::io::Result<TokioUnixStream> {
        let socket = self.second();
        socket.set_nonblocking(true)?;
        TokioUnixStream::from_std(socket)
    }
}
