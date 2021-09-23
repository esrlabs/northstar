use std::{env, fs, io};

fn main() -> io::Result<()> {
    for arg in env::args().skip(1) {
        let greet = fs::read_to_string(&arg).unwrap_or(format!("No such file: {}", arg));
        ferris_says::say(greet.as_bytes(), 100, &mut std::io::stdout())?;
    }
    Ok(())
}
