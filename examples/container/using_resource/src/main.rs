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

use std::process::Command;
use yaml_rust::YamlLoader;

fn interpret(aloha: &str) -> std::io::Result<()> {
    let output = Command::new("./res/interpreter/interpreter")
        .arg(format!("{} from \"using_resource\"", aloha))
        .output()?;
    if !output.status.success() {
        println!("Calling the interpreter failed");
    } else {
        let res = String::from_utf8(output.stdout).expect("Could not convert to string");
        println!("{}", res);
    }
    Ok(())
}
fn main() {
    match std::fs::read_to_string("./res/text/config.yaml") {
        Ok(config_string) => match YamlLoader::load_from_str(&config_string) {
            Ok(config_yaml) => {
                // Multi document support, doc is a yaml::Yaml
                let config = &config_yaml[0];

                // Debug support
                let what_to_say = &config["name"]
                    .as_str()
                    .expect("no 'name' field found in config");
                interpret(what_to_say).expect("failed to execute process");
            }
            Err(e) => println!("Could not parse config string: {}", e),
        },
        Err(e) => println!("Could not read config.yaml: {}", e),
    }
}
