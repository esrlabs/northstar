use std::{thread::sleep, time::Duration};

const PERIOD: Duration = Duration::from_millis(100);

fn main() {
    for n in (1..=10).rev() {
        println!("Crashing in {:.1}s", (PERIOD * n).as_secs_f32());
        sleep(PERIOD);
    }

    println!("BOOM!");
    panic!();
}
