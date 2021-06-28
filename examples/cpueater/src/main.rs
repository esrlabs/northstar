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

use std::env::var;

fn main() {
    let version = var("VERSION").expect("Failed to read VERSION");
    let threads = var("THREADS")
        .expect("Failed to read THREADS")
        .parse::<i32>()
        .expect("Invalid thread count");

    println!("Eating CPU with {} threads (v{})!", threads, version);

    for _ in 0..(threads - 1) {
        std::thread::spawn(move || loop {
            let (tx, rx) = std::sync::mpsc::channel();
            tx.send(0).expect("Channel error");
            rx.recv().expect("Channel error");
        });
    }

    loop {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(0).expect("Channel error");
        rx.recv().expect("Channel error");
    }
}
