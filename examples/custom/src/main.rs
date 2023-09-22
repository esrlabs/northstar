use anyhow::{anyhow, Result};
use northstar_client::Client;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut client = Client::from_env(None).await?;
    let container = client.ident().await?;

    // Acquire the custom section for a container from the runtime.
    let custom = client.inspect(container).await?.manifest.custom;

    // Extract the hello property from the custom section of the manifest.
    let again = custom
        .as_ref()
        .and_then(|c| c.as_object())
        .and_then(|c| c.get("properties"))
        .and_then(|c| c.get("hello"))
        .ok_or_else(|| anyhow!("hello property not found in custom manifest"))?
        .as_str()
        .ok_or_else(|| anyhow!("invalid hello property in custom manifest"))?;

    println!("hello {again}");
    Ok(())
}
