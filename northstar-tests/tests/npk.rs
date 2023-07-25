use anyhow::Result;
use northstar_runtime::npk::{
    manifest::Manifest,
    npk::{self, Compression, NpkBuilder, FS_IMG_NAME, MANIFEST_NAME},
};
use std::{
    fs::{self},
    io,
    path::{Path, PathBuf},
    str::FromStr,
};
use tempfile::TempDir;
use zip::ZipArchive;

const TEST_KEY_NAME: &str = "test_key";
const TEST_CONTAINER_NAME: &str = "hello-0.0.2.npk";
const TEST_MANIFEST: &str = "name: hello
version: 0.0.2
init: /hello
uid: 100
gid: 1
env:
  HELLO: north";

struct Fixture {
    manifest_path: PathBuf,
    manifest: Manifest,
    root: PathBuf,
    dir: PathBuf,
    tmpdir: TempDir,
    key_prv: PathBuf,
}

impl Default for Fixture {
    fn default() -> Self {
        let tmpdir = tmpdir();
        let dir = tmpdir.path().to_path_buf();
        let root = root(tmpdir.path()).expect("create root");
        let manifest_path = tmpdir.path().join(MANIFEST_NAME);
        fs::write(&manifest_path, TEST_MANIFEST).expect("write manifest");
        let manifest = Manifest::from_str(TEST_MANIFEST).expect("parse manifest");
        let (_, key_prv) = generate_test_key(tmpdir.path());
        Self {
            manifest_path,
            manifest,
            root,
            dir,
            tmpdir,
            key_prv,
        }
    }
}

#[test]
fn pack_with_manifest_file() -> Result<()> {
    let fixture = Fixture::default();

    let npk = NpkBuilder::default()
        .manifest_path(&fixture.manifest_path)
        .root(&fixture.root, None)
        .to_dir(fixture.tmpdir.path())?
        .0;

    assert!(fixture.dir.join(TEST_CONTAINER_NAME).exists());
    assert_test_manifest(&npk)?;
    assert_root(&npk)?;

    Ok(())
}

#[test]
fn pack_without_key() -> Result<()> {
    let fixture = Fixture::default();

    let npk = NpkBuilder::default()
        .manifest(&fixture.manifest)
        .root(&fixture.root, None)
        .to_dir(fixture.tmpdir.path())?
        .0;

    assert!(fixture.dir.join(TEST_CONTAINER_NAME).exists());
    assert_test_manifest(&npk)?;
    assert_root(&npk)?;

    Ok(())
}

#[test]
fn pack_with_key() -> Result<()> {
    let fixture = Fixture::default();

    let npk = NpkBuilder::default()
        .manifest(&fixture.manifest)
        .root(&fixture.root, None)
        .key(&fixture.key_prv)
        .to_dir(&fixture.dir)?
        .0;

    assert!(fixture.dir.join(TEST_CONTAINER_NAME).exists());
    assert_test_manifest(&npk)?;
    assert_root(&npk)?;

    Ok(())
}

#[test]
fn pack_with_compression_none() -> Result<()> {
    pack_with_compression(Compression::None)
}

#[test]
fn pack_with_compression_gzip() -> Result<()> {
    pack_with_compression(Compression::Gzip)
}

#[test]
fn pack_with_compression_lzma() -> Result<()> {
    pack_with_compression(Compression::Lzma)
}

#[test]
fn pack_with_compression_lzo() -> Result<()> {
    pack_with_compression(Compression::Lzo)
}

#[test]
fn pack_with_compression_xz() -> Result<()> {
    pack_with_compression(Compression::Xz)
}

#[test]
fn pack_with_compression_zstd() -> Result<()> {
    pack_with_compression(Compression::Zstd)
}

#[test]
fn pack_with_fs_image() -> Result<()> {
    let fixture = Fixture::default();

    // Pack a npk in order to obtain a fs image.
    // Do not use a key here.
    let npk = NpkBuilder::default()
        .manifest(&fixture.manifest)
        .root(&fixture.root, None)
        .to_dir(&fixture.dir)?
        .0;

    // Get fs image from npk.
    let mut zip = ZipArchive::new(fs::File::open(&npk)?)?;
    let mut fs_img_zip = zip.by_name(FS_IMG_NAME)?;
    let fs_img_path = fixture.dir.join(FS_IMG_NAME);
    let mut fs_img = fs::File::create(&fs_img_path)?;
    io::copy(&mut fs_img_zip, &mut fs_img)?;

    NpkBuilder::default()
        .manifest(&fixture.manifest)
        .fsimage(&fs_img_path)
        .to_file(&npk)?;

    assert!(npk.exists());
    assert_test_manifest(&npk)?;
    assert_root(&npk)?;

    Ok(())
}

#[test]
fn pack_with_manifest_root_and_fsimage_should_fail() -> Result<()> {
    let fixture = Fixture::default();
    let result = NpkBuilder::default()
        .manifest(&fixture.manifest)
        .root(&fixture.root, None)
        .fsimage(&fixture.root)
        .to_dir(&fixture.dir);

    assert!(result.is_err());

    Ok(())
}

#[test]
fn pack_to_file() -> Result<()> {
    let fixture = Fixture::default();
    let npk = fixture.dir.join("test.npk");

    NpkBuilder::default()
        .manifest(&fixture.manifest)
        .root(&fixture.root, None)
        .key(&fixture.key_prv)
        .to_file(&npk)?;

    assert!(npk.exists());
    assert_test_manifest(&npk)?;
    assert_root(&npk)?;

    Ok(())
}

#[test]
fn pack_to_writer() -> Result<()> {
    let fixture = Fixture::default();
    let npk_path = fixture.dir.join("test.nkp");
    let npk = fs::File::create(&npk_path)?;

    NpkBuilder::default()
        .manifest(&fixture.manifest)
        .root(&fixture.root, None)
        .key(&fixture.key_prv)
        .to_writer(npk)?;

    assert!(npk_path.exists());
    assert_test_manifest(&npk_path)?;
    assert_root(&npk_path)?;

    Ok(())
}

fn generate_test_key(key_dir: &Path) -> (PathBuf, PathBuf) {
    npk::generate_key(TEST_KEY_NAME, key_dir).expect("Generate key pair");
    let prv_key = key_dir.join(TEST_KEY_NAME).with_extension("key");
    let pub_key = key_dir.join(TEST_KEY_NAME).with_extension("pub");
    assert!(prv_key.exists());
    assert!(pub_key.exists());
    (pub_key, prv_key)
}

fn tmpdir() -> TempDir {
    TempDir::new().expect("failed to create tempdir")
}

fn root(tmpdir: &Path) -> Result<PathBuf> {
    let root = tmpdir.join("root");
    fs::create_dir_all(&root)?;
    fs::create_dir(root.join("bin"))?;
    fs::create_dir(root.join("etc"))?;
    fs::create_dir(root.join("lib"))?;
    fs::File::create(root.join("foo"))?;
    fs::File::create(root.join("etc").join("hosts"))?;
    Ok(root)
}

fn assert_root(npk: &Path) -> Result<()> {
    let tmpdir = tmpdir();
    npk::unpack(npk, tmpdir.path())?;
    let root = tmpdir.path().join("root");
    assert!(root.join("bin").is_dir());
    assert!(root.join("etc").is_dir());
    assert!(root.join("lib").is_dir());
    assert!(root.join("foo").is_file());
    assert!(root.join("etc").join("hosts").is_file());
    Ok(())
}

fn pack_with_compression(compression: Compression) -> Result<()> {
    let fixture = Fixture::default();
    let squashfs_options = npk::SquashfsOptions {
        compression,
        ..Default::default()
    };

    NpkBuilder::default()
        .manifest(&fixture.manifest)
        .root(&fixture.root, Some(&squashfs_options))
        .key(&fixture.key_prv)
        .to_dir(&fixture.dir)?;

    assert!(fixture.dir.join(TEST_CONTAINER_NAME).exists());
    Ok(())
}

fn assert_test_manifest(npk: &Path) -> Result<()> {
    let tmpdir = tmpdir();
    npk::unpack(npk, tmpdir.path())?;
    let test_manifest = Manifest::from_str(TEST_MANIFEST)?;
    let manifest = Manifest::from_reader(fs::File::open(tmpdir.path().join(MANIFEST_NAME))?)?;
    assert_eq!(manifest, test_manifest);
    Ok(())
}
