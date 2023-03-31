use anyhow::{Context, Result};
use std::{
    env,
    io::{Read, Write},
    os::{
        fd::FromRawFd,
        unix::net::{UnixListener, UnixStream},
    },
    path::Path,
    thread, time,
};

fn main() -> Result<()> {
    let server = thread::spawn(server);
    let client = thread::spawn(client);

    server.join().expect("server join error")?;
    client.join().expect("client join error")?;
    Ok(())
}

fn server() -> Result<()> {
    let stream_fd = env::var("NORTHSTAR_SOCKET_hello-stream")?.parse()?;
    println!("Got stream fd {stream_fd}");
    let listener = unsafe { UnixListener::from_raw_fd(stream_fd) };
    println!("Accepting connections...");

    loop {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                println!("Serving new connection from {peer:?}");
                thread::spawn(move || -> Result<()> {
                    let mut buf = [0; 1024];
                    loop {
                        match stream.read(&mut buf) {
                            Ok(n) if n == 0 => break Ok(()),
                            Ok(n) => stream.write_all(&buf[..n]).context("failed to write")?,
                            Err(e) => {
                                println!("Read error: {e}");
                                break Err(e.into());
                            }
                        }
                    }
                });
            }
            Err(e) => {
                println!("Listen error: {e}");
                break Ok(());
            }
        }
    }
}

// The socket directory is bind mounted to /unix-sockets. See manifest.yaml.
// The code below normally runs in a different container...
fn client() -> Result<()> {
    let container = "sockets";
    let socket_name = "hello-stream";

    let path = Path::new("/unix-sockets").join(container).join(socket_name);

    println!("Connecting to {}", path.display());
    let mut stream = UnixStream::connect(path)?;

    let mut text = b"hello!\n".to_vec();
    loop {
        println!("Saying hello!");
        stream.write_all(&text)?;
        stream.read_exact(&mut text)?;
        println!("Received {}", String::from_utf8(text.clone())?.trim());

        thread::sleep(time::Duration::from_secs(1));
    }
}
