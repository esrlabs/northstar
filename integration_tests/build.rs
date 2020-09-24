// one line to give the program's name and a brief description
// Copyright 2020 yourname
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{env, process};

pub fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!(
        "cargo:rerun-if-changed={}/test_container/src/main.rs",
        manifest_dir
    );

    process::Command::new("bundle")
        .args(&["exec", "rake", "test_container:build"])
        .output()
        .expect("Failed to build the test container");
}
