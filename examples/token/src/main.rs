use anyhow::Result;
use northstar::api::client;
use std::{env, os::unix::prelude::FromRawFd, time::Duration};
use tokio::net::UnixStream;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Connect to the runtime via NORTHSTAR_CONSOLE...
    let fd = env::var("NORTHSTAR_CONSOLE")?.parse::<i32>()?;
    let std = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    std.set_nonblocking(true)?;
    let io = UnixStream::from_std(std)?;
    let mut client = client::Client::new(io, None, Duration::from_secs(5)).await?;

    // Get the container name of this instance
    let ident = client.ident().await?;
    println!("We are {}", ident);

    // Target and user are identical 🤷
    let user: &str = ident.name().as_ref();
    let target: &str = ident.name().as_ref();
    let shared = "hello!";

    // Create a token that can be used to verify `shared`. Note that there's
    // no `user` argument here. The runtime know from which container the request
    // is from.
    println!(
        "Creating token for target \"{}\" with shared \"{}\"",
        target, shared,
    );
    let token = client.create_token(target, shared).await?;

    // The token can be used to verify `shared` from a container named `target`.

    // Verify that token was issued with "hello!"
    println!("Verifying user \"{}\" with shared \"{}\"", user, shared);
    let verified = client.verify_token(&token, user, shared).await?;
    println!("Verification result of \"{}\" is {:?}", shared, verified);

    println!("Verifying user \"{}\" with shared \"hamster\"", user);
    let verified = client.verify_token(&token, user, "hamster").await?;
    println!("Verification result of \"hamster\" is {:?}", verified);

    Ok(())
}
