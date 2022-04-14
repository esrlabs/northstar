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

    // Create a token that can be used to verify "hello!"
    println!("Creating token with \"hello!\"");
    let token = client.create_token("hello!").await?;

    // Verify that token was issued with "hello!"
    println!("Verifying \"hello!\"");
    let verified = client.verify_token(&token, "hello!").await?;
    println!("Verification result of \"hello!\" is {:?}", verified);

    println!("Verifying \"hamster\"");
    let verified = client.verify_token(&token, "hamster").await?;
    println!("Verification result of \"hamster\" is {:?}", verified);

    Ok(())
}
