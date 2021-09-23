use std::time::Duration;

fn main() {
    let mut n = 10;
    loop {
        if n == 0 {
            println!("BOOM!");
            panic!("BOOM");
        }
        println!("Crashing in {} seconds", n);
        std::thread::sleep(Duration::from_secs(1));
        n -= 1;
    }
}
