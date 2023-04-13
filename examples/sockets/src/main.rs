use std::{
    env,
    os::{fd::FromRawFd, unix::net::UnixDatagram},
    path::Path,
    thread,
};

fn main() {
    let server = thread::spawn(server);
    let client = thread::spawn(client);

    server.join().expect("server join error");
    client.join().expect("client join error");
}

fn server() {
    let stream_fd = env::var("NORTHSTAR_SOCKET_hello")
        .expect("missing socket variable")
        .parse()
        .expect("failed to parse socket variable");
    let socket = unsafe { UnixDatagram::from_raw_fd(stream_fd) };
    let mut buf = [0; 1024];
    let buf = socket
        .recv(&mut buf)
        .map(|n| &buf[..n])
        .expect("failed to receive");
    println!(
        "Received {}",
        String::from_utf8(buf.to_vec())
            .expect("invalid data")
            .trim()
    );
}

// The socket directory is bind mounted to /unix-sockets. See manifest.yaml.
// The code below normally runs in a different container...
fn client() {
    // Socket path.
    let path = Path::new("/unix-sockets").join("sockets").join("hello");

    println!("Connecting to {}", path.display());
    let socket = UnixDatagram::unbound().expect("failed to create socket");
    socket.connect(path).expect("failed to connect");
    socket.send("Hello!".as_bytes()).expect("failed to send");
}
