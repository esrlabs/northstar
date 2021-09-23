use std::env::var;

fn main() {
    let version = var("VERSION").expect("Failed to read VERSION");
    let threads = var("THREADS")
        .expect("Failed to read THREADS")
        .parse::<i32>()
        .expect("Invalid thread count");

    println!("Eating CPU with {} threads (v{})!", threads, version);

    for _ in 0..(threads - 1) {
        std::thread::spawn(move || loop {
            let (tx, rx) = std::sync::mpsc::channel();
            tx.send(0).expect("Channel error");
            rx.recv().expect("Channel error");
        });
    }

    loop {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(0).expect("Channel error");
        rx.recv().expect("Channel error");
    }
}
