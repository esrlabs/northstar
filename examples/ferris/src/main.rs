const FERRIS: &str = r#"
        \
         \
            _~^~^~_
        \) /  o o  \ (/
          '_   -   _'
          / '-----' \
"#;

fn main() -> std::io::Result<()> {
    for arg in std::env::args().skip(1) {
        let greet = std::fs::read_to_string(&arg)?;
        println!("{}", greet);
        println!("{}", FERRIS);
    }
    Ok(())
}
