use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
    process::Command,
};

use anyhow::{Context, Result};
use colored::Colorize;

use northstar_runtime::npk::npk::{Npk, FS_IMG_NAME, MANIFEST_NAME, SIGNATURE_NAME};
use zip::ZipArchive;

pub(crate) fn inspect(npk: &Path, short: bool, unsquashfs: &Path) -> Result<()> {
    if short {
        inspect_short(npk)
    } else {
        inspect_long(npk, unsquashfs)
    }
}

pub(crate) fn inspect_short(npk: &Path) -> Result<()> {
    let npk = Npk::<BufReader<File>>::from_path(npk, None)?;
    let manifest = npk.manifest();
    let name = manifest.name.to_string();
    let version = manifest.version.to_string();
    let npk_version = npk.version();
    let is_resource_container = manifest.init.as_ref().map_or("yes", |_| "no");
    println!(
        "name: {name}, version: {version}, NPK version: {npk_version}, resource container: {is_resource_container}",
    );

    Ok(())
}

fn open(path: &Path) -> Result<ZipArchive<BufReader<std::fs::File>>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open '{}'", &path.display()))?;
    ZipArchive::new(BufReader::new(file))
        .with_context(|| format!("failed to parse ZIP format: '{}'", &path.display()))
}

pub(crate) fn inspect_long(npk: &Path, unsquashfs: &Path) -> Result<()> {
    let mut zip = open(npk)?;
    let mut print_buf: String = String::new();
    println!(
        "{}",
        format!("# inspection of '{}'", &npk.display()).green()
    );
    println!("{}", "## NPK Content".to_string().green());
    zip.file_names().for_each(|f| println!("{f}"));
    println!();

    // print manifest
    let mut man = zip
        .by_name(MANIFEST_NAME)
        .context("failed to find manifest in NPK")?;
    println!("{}", format!("## {MANIFEST_NAME}").green());
    man.read_to_string(&mut print_buf)
        .with_context(|| "failed to read manifest")?;
    println!("{}", &print_buf);
    print!("\n\n");
    print_buf.clear();
    drop(man);

    // print signature
    match zip.by_name(SIGNATURE_NAME) {
        Ok(mut sig) => {
            println!("{}", format!("## {SIGNATURE_NAME}").green());
            sig.read_to_string(&mut print_buf)
                .with_context(|| "failed to read signature")?;
            println!("{}", &print_buf);
            print!("\n\n");
            print_buf.clear();
            drop(sig);
        }
        _ => println!("No signature found"),
    }

    // print squashfs listing
    println!("{}", "## SquashFS listing".green());
    let mut dest_fsimage = tempfile::NamedTempFile::new().context("failed to create tmp file")?;
    let mut src_fsimage = zip
        .by_name(FS_IMG_NAME)
        .context("failed to find filesystem image in NPK")?;
    io::copy(&mut src_fsimage, &mut dest_fsimage)?;
    let path = dest_fsimage.path();
    print_squashfs(path, unsquashfs)?;

    Ok(())
}

fn print_squashfs(fsimg_path: &Path, unsquashfs: &Path) -> Result<()> {
    let mut cmd = Command::new(unsquashfs);
    cmd.arg("-ll").arg(fsimg_path.display().to_string());

    let output = cmd
        .output()
        .with_context(|| format!("failed to execute '{}'", unsquashfs.display()))?;

    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}

#[cfg(test)]
mod test {
    use super::inspect;
    use northstar_runtime::npk::npk::{generate_key, NpkBuilder};
    use std::{
        fs::File,
        io::Write,
        path::{Path, PathBuf},
    };
    use tempfile::TempDir;

    const TEST_KEY_NAME: &str = "test_key";
    const TEST_MANIFEST: &str = "name: hello
version: 0.0.2
init: /hello
env:
  HELLO: north
# autostart: true
uid: 1000
gid: 1000
mounts:
    /lib:
      type: bind
      host: /lib
    /lib64:
      type: bind
      host: /lib64
    /system:
      type: bind
      host: /system";

    fn create_test_npk(dest: &Path) -> PathBuf {
        let src = create_tmp_dir();
        let key_dir = create_tmp_dir();
        let manifest = create_test_manifest(src.path());
        let (_pub_key, prv_key) = gen_test_key(key_dir.path());
        NpkBuilder::default()
            .manifest_path(&manifest)
            .root(src.path(), None)
            .key(&prv_key)
            .to_dir(dest)
            .expect("failed to pack npk")
            .0
    }

    fn create_test_manifest(src: &Path) -> PathBuf {
        let manifest = src.join("manifest").with_extension("yaml");
        File::create(&manifest)
            .expect("Create manifest.yaml")
            .write_all(TEST_MANIFEST.as_ref())
            .expect("Write test manifest");
        manifest
    }

    fn create_tmp_dir() -> TempDir {
        TempDir::new().expect("Create tmp dir")
    }

    fn gen_test_key(key_dir: &Path) -> (PathBuf, PathBuf) {
        generate_key(TEST_KEY_NAME, key_dir).expect("Generate key pair");
        let prv_key = key_dir.join(TEST_KEY_NAME).with_extension("key");
        let pub_key = key_dir.join(TEST_KEY_NAME).with_extension("pub");
        assert!(prv_key.exists());
        assert!(pub_key.exists());
        (pub_key, prv_key)
    }

    #[test]
    fn inspect_npk() {
        let dest = create_tmp_dir();
        let npk = create_test_npk(dest.path());
        assert!(npk.exists());
        inspect(&npk, true, Path::new("unsquashfs")).expect("Inspect NPK");
        inspect(&npk, false, Path::new("unsquashfs")).expect("Inspect NPK");
    }

    #[test]
    fn inspect_npk_no_file() {
        inspect(Path::new("invalid"), true, Path::new("unsquashfs")).expect_err("invalid NPK");
        inspect(Path::new("invalid"), false, Path::new("unsquashfs")).expect_err("invalid NPK");
    }
}
