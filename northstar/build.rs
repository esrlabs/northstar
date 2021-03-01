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

use vergen::{generate_cargo_keys, ConstantsFlags};

fn main() {
    let flags = ConstantsFlags::BUILD_TIMESTAMP
        | ConstantsFlags::TARGET_TRIPLE
        | ConstantsFlags::SHA_SHORT
        | ConstantsFlags::SEMVER_FROM_CARGO_PKG;
    generate_cargo_keys(flags).expect("Unable to generate the cargo keys!");

    #[cfg(debug_assertions)]
    package_hello_example().expect("Failed to package hello-world");
}

#[cfg(debug_assertions)]
pub fn package_hello_example() -> anyhow::Result<()> {
    use anyhow::Context;
    use npk::npk;
    use std::{env, fs, path::Path};
    use tokio::runtime;

    const MANIFEST: &str = r#"name: hello-world
version: 0.0.1
uid: 1000
gid: 1000
init: /bin/sh
args:
  - "-c"
  - "echo Hello World!"
io:
  stdout: pipe
mounts:
  /bin:
    host: /bin
  /lib:
    host: /lib
  /lib64:
    host: /lib64"#;

    const MANIFEST_ANDROID: &str = r#"name: hello-world
version: 0.0.1
uid: 1000
gid: 1000
init: /system/bin/sh
io:
  stdout: pipe
args:
  - "-c"
  - "echo Hello World!"
mounts:
  /system:
    host: /system"#;

    let out_dir = env::var("OUT_DIR").context("Failed to read OUT_DIR")?;
    let out_dir = Path::new(&out_dir);

    let root_dir = out_dir.join("root");
    fs::create_dir_all(&root_dir).context("Failed to create root dir")?;

    let manifest = match env::var("CARGO_CFG_TARGET_OS")
        .context("Failed to read CARGO_CFG_TARGET_OS")?
        .as_str()
    {
        "android" => MANIFEST_ANDROID,
        _ => MANIFEST,
    };
    let manifest_file = out_dir.join("manifest.yaml");
    std::fs::write(&manifest_file, &manifest).context("Failed to create manifest")?;

    runtime::Builder::new_multi_thread()
        .enable_io()
        .build()?
        .block_on(npk::pack_with(
            &manifest_file,
            &root_dir,
            &out_dir,
            None,
            npk::SquashfsOpts {
                comp: None,
                block_size: None,
            },
        ))?;
    Ok(())
}
