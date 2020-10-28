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

use std::fs;

#[allow(clippy::all)]
fn main() {
    let mut mem = vec![];
    for _ in 0..9_999_999 {
        println!("I've consumed {} bytes", get_used_memory_in_bytes());
        let mut chunk = vec![];
        for i in 0..1_000_000 {
            chunk.push((i % 8) as u8);
        }
        mem.push(chunk);
        std::thread::sleep(std::time::Duration::from_millis(400));
    }

    // just something to make the compiler not optimize....
    for x in &mem {
        println!("{}", x[0]);
    }
}

/// Returns the amount in bytes corresponding to all the memory pages maped by the process.
fn get_used_memory_in_bytes() -> u64 {
    let stat = fs::read_to_string("/proc/self/stat").expect("Could not read /proc/self/stat");
    let mut fields = stat.split_whitespace();

    // Read the Resident Set Size (RSS).
    // This number correspond to the total number of memory pages used by the process.
    // This includes also the shared libraries which means that the final count is larger
    // than the real amount of bytes consumed by the process.
    let rss = fields
        .nth(23)
        .expect("Could not read RSS memory usage")
        .parse::<u64>()
        .expect("Could not parse RSS");

    // Usually the page size is set to 4kB by default
    let page_size = 4096;

    rss * page_size
}
