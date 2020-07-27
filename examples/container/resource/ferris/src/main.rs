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

use std::{fs, io};

fn main() -> io::Result<()> {
    std::env::args()
        .nth(0)
        .ok_or(io::Error::new(
            io::ErrorKind::Other,
            "Missing or invalid arguments",
        ))
        .map(|greeting| fs::read_to_string(&greeting).unwrap_or(greeting))
        .and_then(|greeting| ferris_says::say(greeting.as_bytes(), 100, &mut std::io::stdout()))
}
