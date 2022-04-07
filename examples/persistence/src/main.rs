use std::{fs, io, io::Write, path::Path, time};

fn main() -> io::Result<()> {
    // In the manifest a mount of type data is configured on target "/data"
    let file = Path::new("/data").join("file");
    let text = "Hello!";

    loop {
        // Write
        let mut f = fs::File::create(&file).expect("failed to create foo");
        println!("Writing {} to {}", text, file.display());
        f.write_all(text.as_bytes())?;

        // Read
        let text = fs::read_to_string(&file)?;
        println!("Content of {}: {}", file.display(), text);
        std::thread::sleep(time::Duration::from_secs(1));
    }
}
