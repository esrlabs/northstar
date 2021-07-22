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

use escargot::CargoBuild;
use northstar::npk;
use std::{env, fs, path::Path};

const KEY: &str = "../examples/northstar.key";

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);

    for dir in &[
        "../examples/cpueater",
        "../examples/crashing",
        "../examples/ferris",
        "../examples/hello-ferris",
        "../examples/hello-resource",
        "../examples/hello-world",
        "../examples/inspect",
        "../examples/memeater",
        "../examples/message-0.0.1",
        "../examples/message-0.0.2",
        "../examples/persistence",
        "../examples/seccomp",
        "test-container",
        "test-resource",
    ] {
        let dir = Path::new(dir);
        // Build crate if a Cargo manifest is included in the directory
        let cargo_manifest = dir.join("Cargo.toml");

        let (root, tmpdir) = if cargo_manifest.exists() {
            println!("Building {}", cargo_manifest.display());
            let bin = CargoBuild::new()
                .manifest_path(cargo_manifest)
                .current_release()
                .target(env::var("TARGET").unwrap())
                .target_dir(Path::new("target").join("tests")) // Cannot reuse target because it's in use
                .run()
                .expect("Failed to build")
                .path()
                .to_owned();

            println!("Binary is {}", bin.display());
            let tmpdir = tempfile::TempDir::new().expect("Failed to create tmpdir");
            let npk = tmpdir.path().join("npk");
            let root = npk.join("root");
            fs::create_dir_all(&root).expect("Failed to create npk root");
            fs::copy(&bin, root.join(dir.file_name().unwrap())).expect("failed to copy bin");
            (root, Some(tmpdir))
        } else {
            let root = dir.join("root");
            if root.exists() {
                (root, None)
            } else {
                (dir.to_owned(), None)
            }
        };

        npk::npk::pack(
            &dir.join(Path::new("manifest.yaml")),
            &root,
            out_dir,
            Some(Path::new(KEY)),
        )
        .expect("Failed to pack npk");
        drop(tmpdir);
    }
}
