use anyhow::{Context, Result};
use northstar::npk::npk::{self, SquashfsOpts};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

const KEY_NAME: &str = "test_key";
const MANIFEST: &str = "name: hello
version: 0.0.2
init: /hello
uid: 100
gid: 1
env:
  HELLO: north";
const MANIFEST_UNPACKED: &str = "---
name: hello
version: 0.0.2
init: /hello
uid: 100
gid: 1
env:
  HELLO: north
";
const AUTHOR: Option<&str> = Some("clown");

#[test]
fn pack() -> Result<()> {
    let tmpdir = TempDir::new().expect("failed to create tempdir");
    let manifest = tmpdir.path().join("manifest.yaml");
    fs::write(&manifest, MANIFEST)?;
    let (_, key) = generate_test_key(tmpdir.path());
    npk::pack(
        &manifest,
        tmpdir.path(),
        tmpdir.path(),
        SquashfsOpts::default(),
        Some(&key),
        AUTHOR,
    )
    .context("failed to pack")
}

#[test]
fn pack_file_dest() -> Result<()> {
    let tmpdir = TempDir::new().expect("failed to create tempdir");
    let manifest = tmpdir.path().join("manifest.yaml");
    fs::write(&manifest, MANIFEST)?;
    let (_, key) = generate_test_key(tmpdir.path());
    let dest = tmpdir.path().join("out");
    npk::pack(
        &manifest,
        tmpdir.path(),
        &dest,
        SquashfsOpts::default(),
        Some(&key),
        AUTHOR,
    )
    .context("failed to pack")?;
    assert!(dest.exists());
    Ok(())
}

#[test]
fn pack_invalid_manifest() {
    let tmpdir = TempDir::new().expect("failed to create tempdir");
    let manifest = tmpdir.path().join("manifest.yaml");
    let (_, key) = generate_test_key(tmpdir.path());
    npk::pack(
        &manifest,
        tmpdir.path(),
        tmpdir.path(),
        SquashfsOpts::default(),
        Some(&key),
        AUTHOR,
    )
    .context("failed to pack")
    .expect_err("pack with invalid manifest");
}

#[test]
fn pack_invalid_root() -> Result<()> {
    let tmpdir = TempDir::new().expect("failed to create tempdir");
    let manifest = tmpdir.path().join("manifest.yaml");
    fs::write(&manifest, MANIFEST)?;
    let (_, key) = generate_test_key(tmpdir.path());
    npk::pack(
        &manifest,
        &tmpdir.path().join("missing"),
        tmpdir.path(),
        SquashfsOpts::default(),
        Some(&key),
        AUTHOR,
    )
    .expect_err("pack with invalid root");
    Ok(())
}

#[test]
fn pack_invalid_key() -> Result<()> {
    let tmpdir = TempDir::new().expect("failed to create tempdir");
    let manifest = tmpdir.path().join("manifest.yaml");
    fs::write(&manifest, MANIFEST)?;
    npk::pack(
        &manifest,
        tmpdir.path(),
        tmpdir.path(),
        SquashfsOpts::default(),
        Some(Path::new("missing")),
        AUTHOR,
    )
    .expect_err("pack with invalid key");
    Ok(())
}

#[test]
fn unpack() -> Result<()> {
    let tmpdir = TempDir::new().expect("failed to create tempdir");
    let manifest = tmpdir.path().join("manifest.yaml");
    fs::write(&manifest, MANIFEST)?;
    let (_, key) = generate_test_key(tmpdir.path());
    let dest = tmpdir.path().join("out");
    npk::pack(
        &manifest,
        tmpdir.path(),
        &dest,
        SquashfsOpts::default(),
        Some(&key),
        AUTHOR,
    )
    .context("failed to pack")?;
    assert!(dest.exists());

    let out = tmpdir.path().join("unpack");
    npk::unpack(&dest, &out)?;
    let manifest_unpacked = fs::read_to_string(out.join("manifest.yaml"))?;
    assert_eq!(manifest_unpacked, MANIFEST_UNPACKED);

    Ok(())
}

#[test]
fn generate_key_pair() {
    let tmpdir = TempDir::new().expect("failed to create tempdir");
    generate_test_key(tmpdir.path());
}

#[test]
fn generate_key_pair_with_invalid_dest() {
    npk::generate_key(KEY_NAME, Path::new("invalid")).expect_err("invalid key dir");
}

#[test]
fn do_not_overwrite_keys() -> Result<(), anyhow::Error> {
    let tmpdir = TempDir::new().expect("failed to create tempdir");
    npk::generate_key(KEY_NAME, tmpdir.path())?;
    npk::generate_key(KEY_NAME, tmpdir.path()).expect_err("cannot overwrite keys");
    Ok(())
}

fn generate_test_key(key_dir: &Path) -> (PathBuf, PathBuf) {
    npk::generate_key(KEY_NAME, key_dir).expect("Generate key pair");
    let prv_key = key_dir.join(&KEY_NAME).with_extension("key");
    let pub_key = key_dir.join(&KEY_NAME).with_extension("pub");
    assert!(prv_key.exists());
    assert!(pub_key.exists());
    (pub_key, prv_key)
}
