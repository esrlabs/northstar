use std::io;

use tokio::signal::unix::{signal, SignalKind};

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    // Listen on localhost:6379
    println!("Listenin on localhost:6379");
    let listener = tokio::net::TcpListener::bind("localhost:6379").await?;

    // Register a (virtual) signal handler
    let mut stop = signal(SignalKind::terminate()).expect("failed to install signal handler");

    // Fire up a redis server
    println!("Starting...");
    mini_redis::server::run(listener, stop.recv())
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}
