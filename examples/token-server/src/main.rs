use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as Base64, Engine as _};
use northstar_client::{
    model::{Token, VerificationResult},
    Client,
};
use tokio::{
    io,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    task,
};

const SHARED: &str = "hello!";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Connect to the runtime via NORTHSTAR_CONSOLE...
    let mut client = Client::from_env(None).await?;

    // Listen on some random port
    let listener = tokio::net::TcpListener::bind("localhost:6543").await?;

    println!("Listening on {}", listener.local_addr()?);

    while let Ok((stream, addr)) = listener.accept().await {
        // The first newline terminated chunk is in the format
        // "<container name> <token>" Read this line and split
        // the two parts.
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let mut split = line.split_whitespace();
        let container = split.next().ok_or_else(|| anyhow!("missing name"))?;
        let token = split
            .next()
            .ok_or_else(|| anyhow!("missing token"))
            .and_then(|t| Base64.decode(t).context("malformed token"))?;
        let token: Token = token.into();

        println!("Verifying user \"{container}\" from {addr} with shared \"{SHARED}\"");

        match client.verify_token(&token, container, SHARED).await? {
            VerificationResult::Ok => {
                println!("Verified! Starting to echo...");

                // Play the echo game
                task::spawn(async move {
                    let buffer = reader.buffer().to_vec();
                    let mut stream = reader.into_inner();
                    let (mut rx, mut tx) = stream.split();
                    tx.write_all(&buffer).await?;
                    let bytes = io::copy(&mut rx, &mut tx).await?;
                    println!("Echoed {bytes} bytes for {addr}");
                    Result::<()>::Ok(())
                });
            }
            e => println!("Failed to verify: {e:?}. Disconnecting..."),
        }
    }
    Ok(())
}
