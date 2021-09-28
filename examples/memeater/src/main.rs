use std::{fs, io::Read, thread, time};

const SIZE: u64 = 100 * 1024;

fn main() {
    let mut leaked = 0;
    loop {
        let mut buffer = Vec::new();
        fs::File::open("/dev/urandom")
            .unwrap()
            .take(SIZE)
            .read_to_end(&mut buffer)
            .unwrap();
        buffer.leak();
        leaked += SIZE;
        println!("Leaked {} KiB", leaked / 1024);

        thread::sleep(time::Duration::from_millis(10));
    }
}
