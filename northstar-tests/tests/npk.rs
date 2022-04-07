use northstar::npk::npk;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

const TEST_KEY_NAME: &str = "test_key";
const TEST_CONTAINER_NAME: &str = "hello-0.0.2.npk";
const TEST_MANIFEST: &str = "name: hello
version: 0.0.2
init: /hello
uid: 100
gid: 1
env:
  HELLO: north";
const TEST_MANIFEST_UNPACKED: &str = "---
name: hello
version: 0.0.2
init: /hello
uid: 100
gid: 1
env:
  HELLO: north
";

fn tmpdir() -> TempDir {
    TempDir::new().expect("failed to create tempdir")
}

fn create(dest: &Path, manifest_name: Option<&str>) {
    let src = tmpdir();
    let key_dir = tmpdir();
    let manifest = create_test_manifest(src.path(), manifest_name);
    let (_, prv_key) = generate_test_key(key_dir.path());
    npk::pack(&manifest, src.path(), dest, Some(&prv_key)).expect("Pack NPK");
}

fn create_test_manifest(dest: &Path, manifest_name: Option<&str>) -> PathBuf {
    let manifest = dest
        .join(manifest_name.unwrap_or("manifest"))
        .with_extension("yaml");
    File::create(&manifest)
        .expect("Create test manifest file")
        .write_all(TEST_MANIFEST.as_ref())
        .expect("Write test manifest");
    manifest
}

fn generate_test_key(key_dir: &Path) -> (PathBuf, PathBuf) {
    npk::generate_key(TEST_KEY_NAME, key_dir).expect("Generate key pair");
    let prv_key = key_dir.join(&TEST_KEY_NAME).with_extension("key");
    let pub_key = key_dir.join(&TEST_KEY_NAME).with_extension("pub");
    assert!(prv_key.exists());
    assert!(pub_key.exists());
    (pub_key, prv_key)
}

#[test]
fn pack() {
    let dest = tmpdir();
    create(dest.path(), None);
}

#[test]
fn pack_with_manifest() {
    let dest = tmpdir();
    create(dest.path(), Some("different_manifest_name"));
}

#[test]
fn pack_missing_manifest() {
    let src = tmpdir();
    let dest = tmpdir();
    let key_dir = tmpdir();
    let manifest = Path::new("invalid");
    let (_pub_key, prv_key) = generate_test_key(key_dir.path());
    npk::pack(manifest, src.path(), dest.path(), Some(&prv_key)).expect_err("invalid manifest");
}

#[test]
fn pack_file_as_destination() {
    let tmp = tmpdir();
    let dest = tmp.path().join("file.npk");
    create(dest.as_path(), None);
}

#[test]
fn pack_invalid_key() {
    let src = tmpdir();
    let dest = tmpdir();
    let manifest = create_test_manifest(src.path(), None);
    let private = Path::new("invalid");
    npk::pack(&manifest, src.path(), dest.path(), Some(private)).expect_err("invalid key dir");
}

#[test]
fn unpack() {
    let npk_dest = tmpdir();
    create(npk_dest.path(), None);
    let npk = npk_dest.path().join(TEST_CONTAINER_NAME);
    assert!(npk.exists());
    let unpack_dest = tmpdir();
    npk::unpack(&npk, unpack_dest.path()).expect("Unpack NPK");
    let manifest = unpack_dest.path().join("manifest").with_extension("yaml");
    assert!(manifest.exists());
    let manifest = fs::read_to_string(&manifest).expect("failed to parse manifest");

    assert_eq!(TEST_MANIFEST_UNPACKED, manifest);
}

#[test]
fn generate_key_pair() {
    let dest = tmpdir();
    generate_test_key(dest.path());
}

#[test]
fn generate_key_pair_no_dest() {
    npk::generate_key(TEST_KEY_NAME, Path::new("invalid")).expect_err("invalid key dir");
}

#[test]
fn do_not_overwrite_keys() -> Result<(), anyhow::Error> {
    let dest = tmpdir();
    npk::generate_key(TEST_KEY_NAME, dest.path()).expect("Generate keys");
    npk::generate_key(TEST_KEY_NAME, dest.path()).expect_err("Cannot overwrite keys");
    Ok(())
}
