use std::path::PathBuf;

use log::debug;
use tokio::{
    fs, io,
    net::{TcpListener, UnixListener},
};
use url::Url;

/// Types of listeners for console connections
pub enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl Listener {
    pub async fn new(url: &Url) -> io::Result<Listener> {
        let listener = match url.scheme() {
            "tcp" => {
                let address = url
                    .socket_addrs(|| Some(4200))?
                    .first()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::Other, format!("invalid url: {url}"))
                    })?
                    .to_owned();
                let listener = TcpListener::bind(&address).await?;
                debug!("Started console on {}", &address);

                Listener::Tcp(listener)
            }
            "unix" => {
                let path = PathBuf::from(url.path());

                // TODO this file should not be deleted here
                if path.exists() {
                    fs::remove_file(&path).await?
                }

                let listener = UnixListener::bind(&path)?;

                debug!("Started console on {}", path.display());
                Listener::Unix(listener)
            }
            _ => unreachable!(),
        };
        Ok(listener)
    }
}
