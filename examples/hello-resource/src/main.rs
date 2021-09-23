use std::{fs, io, path::PathBuf};
fn main() -> io::Result<()> {
    for i in 0..u64::MAX {
        for entry in fs::read_dir(PathBuf::from("/message"))? {
            let path = entry?.path();
            if path.is_file() {
                let resource_content = fs::read_to_string(&path)?;
                println!("{}: Content of {}: {}", i, path.display(), resource_content);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Ok(())
}
