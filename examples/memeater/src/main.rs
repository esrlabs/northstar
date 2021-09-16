// Copyright (c) 2019 - 2021 ESRLabs
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

use std::{fs, io::Read, thread};

const MB: u64 = 1000000;

fn main() {
    let mut allocated: usize = 0;
    loop {
        let mut buffer = Vec::new();
        fs::File::open("/dev/urandom")
            .unwrap()
            .take(MB)
            .read_to_end(&mut buffer)
            .unwrap();
        buffer.leak();
        allocated += 1;
        println!("Leaked {} MB", allocated);

        thread::sleep(std::time::Duration::from_millis(200));
    }
}
