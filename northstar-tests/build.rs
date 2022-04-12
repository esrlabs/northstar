use escargot::CargoBuild;
use northstar::npk::npk::{pack, SquashfsOpts};
use std::{env, fs, path::Path};

const KEY: &str = "../examples/northstar.key";

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);

    for dir in &[
        "../examples/cpueater",
        "../examples/console",
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

        // Rerun this script if the source or manifest is updated
        println!("cargo:rerun-if-changed={}/manifest.yaml", dir.display());
        let src_dir = dir.join("src");
        if src_dir.exists() {
            println!("cargo:rerun-if-changed={}", src_dir.display());
        }

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
                .expect("failed to build")
                .path()
                .to_owned();

            println!("Binary is {}", bin.display());
            let tmpdir = tempfile::TempDir::new().expect("failed to create tmpdir");
            let npk = tmpdir.path().join("npk");
            let root = npk.join("root");
            fs::create_dir_all(&root).expect("failed to create npk root");
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

        pack(
            &dir.join("manifest.yaml"),
            &root,
            out_dir,
            SquashfsOpts::default(),
            Some(Path::new(KEY)),
            Some("northstar-tests"),
        )
        .expect("failed to pack npk");
        drop(tmpdir);
    }
}
