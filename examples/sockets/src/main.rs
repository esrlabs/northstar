fn main() {
    for _ in 0..u64::MAX {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
