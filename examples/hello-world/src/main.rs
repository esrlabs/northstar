fn main() {
    let hello = std::env::var("NORTHSTAR_CONTAINER").unwrap_or_else(|_| "unknown".into());

    println!("Hello again {}!", hello);
    for i in 0..u64::MAX {
        println!("...and hello again #{} {} ...", i, hello);
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
