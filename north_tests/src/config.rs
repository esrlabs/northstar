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

use color_eyre::eyre::WrapErr;
use lazy_static::lazy_static;
use north::runtime::config::Config;

lazy_static! {
    static ref NORTH_CONFIG: Config = {
        let content = std::fs::read_to_string("north.toml")
            .wrap_err("Failed to read north.toml")
            .unwrap();
        toml::from_str(&content)
            .wrap_err("Failed to parse north.toml")
            .unwrap()
    };
}

pub fn default_config() -> &'static Config {
    &NORTH_CONFIG
}
