use escargot::CargoBuild;
use rayon::prelude::*;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

const KEY: &str = "../examples/northstar.key";
const ENV_FORCE_BUILD: &str = "NORTHSTAR_FORCE_BUILD";
const NPKS: &[&str] = &[
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
    "../examples/redis",
    "../examples/redis-client",
    "../examples/persistence",
    "../examples/seccomp",
    "../examples/token-client",
    "../examples/token-server",
    "test-container",
    "test-resource",
];

fn main() {
    let out_dir = env::var("OUT_DIR").expect("failed to read OUT_DIR");
    let out_dir = Path::new(&out_dir);
    let sextant = find_or_build_sextant();
    let tmpdir = TempDir::new().expect("failed to create tmpdir");

    NPKS.par_iter().for_each(|dir| {
        let npk = Path::new(dir);
        let northstar_manifest = npk.join("manifest.yaml");
        let cargo_manifest = npk.join("Cargo.toml");
        let binary_name = npk.file_name().unwrap().to_str().unwrap();

        // Rerun this script if the source or manifest(s) are updated
        println!("cargo:rerun-if-changed={}", npk.display());

        // If the npk is a Rust crate use a binary already built or try to build it.
        let root = if cargo_manifest.exists() {
            // The binary name should be the directory name
            let binary_path = CargoBuild::new()
                .manifest_path(cargo_manifest)
                .current_release()
                .target(env::var("TARGET").expect("failed to read TARGET"))
                .target_dir(Path::new("..").join("target").join("northstar-tests")) // Cannot reuse target because it's in use
                .run()
                .expect("failed to build")
                .path()
                .to_owned();
            println!("Using {} for {}", binary_path.display(), npk.display());

            // Create fs root
            let root = tmpdir.path().join(binary_name);
            fs::create_dir(&root).expect("failed to create root in tmpdir");

            // Copy binary into npk root
            fs::copy(&binary_path, root.join(binary_name)).expect("failed to copy binary");
            root
        } else {
            let root = npk.join("root");
            if root.exists() {
                root
            } else {
                npk.to_owned()
            }
        };

        Command::new(&sextant)
            .arg("pack")
            .arg("-o")
            .arg(out_dir)
            .arg("-m")
            .arg(&northstar_manifest)
            .args(["-k", KEY])
            .arg("-r")
            .arg(root)
            .spawn()
            .unwrap_or_else(|_| panic!("failed to spawn sextant for {}", npk.display()))
            .wait()
            .expect("failed to pack");
    });

    tmpdir.close().expect("failed to remove tmpdir");
}

/// Find a sextant binary in the current target directory tree or built is if not present.
fn find_or_build_sextant() -> PathBuf {
    if env::var(ENV_FORCE_BUILD).is_ok() {
        for dir in Path::new(&env::var("OUT_DIR").unwrap()).ancestors() {
            let sextant = dir.join("sextant");
            if sextant.is_file() {
                println!("cargo:warning=Using sextant binary {}", sextant.display());
                return sextant;
            }
        }
    }

    CargoBuild::new()
        .manifest_path("../tools/sextant/Cargo.toml")
        .bin("sextant")
        .current_release()
        .target_dir(Path::new("..").join("target").join("northstar-tests")) // Cannot reuse target because it's in use
        .run()
        .expect("failed to build")
        .path()
        .to_owned()
}
