use anyhow::Result;
use std::{
    env,
    os::{fd::FromRawFd, unix::net::UnixDatagram},
    path::Path,
    thread,
};

fn main() -> Result<()> {
    let server = thread::spawn(server);
    let client = thread::spawn(client);

    server.join().expect("server join error")?;
    client.join().expect("client join error")?;
    Ok(())
}

fn server() -> Result<()> {
    let stream_fd = env::var("NORTHSTAR_SOCKET_hello")?.parse()?;
    let socket = unsafe { UnixDatagram::from_raw_fd(stream_fd) };
    let mut buf = [0; 1024];
    let buf = socket.recv(&mut buf).map(|n| &buf[..n])?;
    println!("Received {}", String::from_utf8(buf.to_vec())?.trim());
    Ok(())
}

// The socket directory is bind mounted to /unix-sockets. See manifest.yaml.
// The code below normally runs in a different container...
fn client() -> Result<()> {
    // Socket path.
    let path = Path::new("/unix-sockets").join("sockets").join("hello");

    println!("Connecting to {}", path.display());
    let socket = UnixDatagram::unbound()?;
    socket.connect(path)?;
    socket.send("Hello!".as_bytes())?;
    Ok(())
}
