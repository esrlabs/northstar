use std::{
    env,
    io::{self, Read, Write},
    os::{
        fd::{FromRawFd, IntoRawFd, OwnedFd},
        unix::net::{UnixDatagram, UnixListener, UnixStream},
    },
    path::Path,
    process, thread,
};

use anyhow::Result;
use nix::sys::socket::{AddressFamily, SockFlag, SockType};

const DATA: &[u8] = b"Hello!";
const ITERATIONS: usize = 10;

/// Perform some basic test on unix sockets provided by the runtime.
pub fn run(socket: &str) -> Result<()> {
    {
        let socket = socket.to_owned();
        thread::spawn(move || listen(&socket))
    };
    connect(socket)?;
    process::exit(0);
}

unsafe fn fd(socket: &str) -> Result<OwnedFd> {
    let fd: i32 = env::var(format!("NORTHSTAR_SOCKET_{socket}"))?.parse()?;
    Ok(OwnedFd::from_raw_fd(fd))
}

fn connect(socket: &str) -> Result<()> {
    let path = Path::new("/unix-sockets")
        .join("test-container")
        .join(socket);

    println!("Connecting to {}", path.display());

    match socket {
        "datagram" => {
            let datagram = UnixDatagram::unbound()?;
            datagram.connect(path)?;
            for _ in 0..ITERATIONS {
                datagram.send(DATA)?;
            }
        }
        "seq-packet" => {
            let socket = nix::sys::socket::socket(
                AddressFamily::Unix,
                SockType::SeqPacket,
                SockFlag::empty(),
                None,
            )?;
            let datagram = unsafe { UnixDatagram::from_raw_fd(socket) };
            datagram.connect(path)?;
            for _ in 0..ITERATIONS {
                datagram.send(DATA)?;
            }
        }
        "stream" => {
            let mut stream = UnixStream::connect(path)?;
            for _ in 0..ITERATIONS {
                println!("Sending data {} bytes", DATA.len());
                stream.write_all(DATA)?;
                let mut buf = vec![0u8; DATA.len()];
                println!("Receiving {} bytes", DATA.len());
                stream.read_exact(&mut buf)?;
                assert_eq!(buf, DATA);
            }
        }
        "no_permission" => {
            assert!(UnixStream::connect(path).is_err());
        }
        _ => panic!("invalid socket: {}", socket),
    }
    Ok(())
}

/// Echo...
fn listen(socket: &str) -> Result<()> {
    let fd = unsafe { fd(socket)? };
    match socket {
        "datagram" | "seq-packet" => {
            let socket = unsafe { UnixDatagram::from_raw_fd(fd.into_raw_fd()) };
            loop {
                let mut buf = vec![0u8; DATA.len()];
                let (len, addr) = socket.recv_from(&mut buf)?;
                println!("Received {} bytes from {:?}", len, addr);
                assert_eq!(buf, DATA);
            }
        }
        "stream" => {
            let socket = unsafe { UnixListener::from_raw_fd(fd.into_raw_fd()) };
            loop {
                let (mut stream, addr) = socket.accept()?;
                println!("Serving connection from {addr:?}");
                thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    loop {
                        let n = stream.read(&mut buf)?;
                        if n == 0 {
                            break io::Result::Ok(());
                        }
                        println!("Forwarding {} bytes", buf[..n].len());
                        stream.write_all(&buf[..n])?;
                    }
                });
            }
        }
        "no_permission" => Ok(()),
        _ => panic!("invalid socket: {}", socket),
    }
}
