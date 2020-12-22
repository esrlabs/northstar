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

use std::{fs, io, path::PathBuf};
fn main() -> io::Result<()> {
    for i in 0..u64::MAX {
        for entry in fs::read_dir(PathBuf::from("/message"))? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let resource_content = fs::read_to_string(&path).unwrap();
                println!(
                    "{}: Content of {}: {}",
                    i,
                    path.to_string_lossy(),
                    resource_content
                );
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Ok(())
}
