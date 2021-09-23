fn main() {
    let hello = std::env::var("HELLO").unwrap_or_else(|_| "unknown".into());
    let version = std::env::var("VERSION").unwrap_or_else(|_| "unknown".into());

    println!("Hello again {} from version {}!", hello, version);
    for i in 0..u64::MAX {
        println!(
            "...and hello again #{} {} from version {}...",
            i, hello, version
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
