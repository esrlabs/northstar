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
    let hello = std::env::var("HELLO").unwrap_or_else(|_| "unknown".into());
    let version = std::env::var("VERSION").unwrap_or_else(|_| "unknown".into());

    println!("Hello again {} from version {}!", hello, version);
    for i in 0..u64::MAX {
        println!(
            "...and hello again #{} {} from version {}...",
            i, hello, version
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
