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

fn main() {
    let mut mem = vec![];
    for _ in 0..9_999_999 {
        println!("Eating a Megabyte... have {}", mem.len());
        let mut chunk = vec![];
        for i in 0..1_000_000 {
            chunk.push((i % 8) as u8);
        }
        mem.push(chunk);
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }

    // just something to make the compiler not optimize....
    for x in &mem {
        println!("{}", x[0]);
    }
}
