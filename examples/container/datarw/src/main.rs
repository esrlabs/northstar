// Copyright (c) 2019 - 2020 ESRLabs
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

use std::{env, fs, io, io::Write, path::PathBuf, time};

const DATA: &str = "DATA";

fn main() -> io::Result<()> {
    // The path to the rw data directory is provided via the env variable "DATA"
    let data = PathBuf::from(env::var(DATA).expect("Cannot read env var DATA"));

    let file = data.join("file");
    let text = "Hello!";

    // Write some text to a file in DATA
    let mut f = fs::File::create(&file).expect("Failed to create foo");
    println!("Writing {} to {}", text, file.display());
    f.write_all(text.as_bytes())?;

    std::thread::sleep(time::Duration::from_secs(1));

    // Read data
    let text = fs::read_to_string(&file)?;
    println!("Context of {}: {}", file.display(), text);

    Ok(())
}
