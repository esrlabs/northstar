use std::env::var;

fn main() {
    let version = var("NORTHSTAR_VERSION").expect("failed to read NORTHSTAR_VERSION");
    let threads = var("THREADS")
        .expect("failed to read THREADS")
        .parse::<i32>()
        .expect("invalid thread count");

    println!("Eating CPU with {threads} threads (v{version})!");

    for _ in 0..(threads - 1) {
        std::thread::spawn(move || loop {
            let (tx, rx) = std::sync::mpsc::channel();
            tx.send(0).expect("channel error");
            rx.recv().expect("channel error");
        });
    }

    loop {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(0).expect("channel error");
        rx.recv().expect("channel error");
    }
}
