use bytes::Bytes;
use mini_redis::client;

const KEY: &str = "hello";
const DATA: &str = "#StandWithUkraine";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let addr = "localhost:6379";
    println!("Connecting to redis://{addr}");
    let mut client = client::connect(addr).await.expect("failed to connect");

    println!("Setting \"{KEY}\" to \"{DATA}\"");
    client
        .set(KEY, Bytes::from_static(DATA.as_bytes()))
        .await
        .unwrap_or_else(|_| panic!("failed to set \"{KEY}\""));

    let get = client
        .get(KEY)
        .await
        .expect("failed to get")
        .expect("key not found");
    println!("Received: {get:#?}");
}
