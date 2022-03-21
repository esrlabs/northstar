fn main() {
    let version = std::env::var("NORTHSTAR_VERSION").unwrap_or_else(|_| "unknown".into());
    loop {
        println!("Hello from the seccomp example version {}!", version);
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
