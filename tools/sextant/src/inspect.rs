use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use northstar::npk::npk::{open, Npk};
use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
    process::Command,
};

const FS_IMG_NAME: &str = "fs.img";
const MANIFEST_NAME: &str = "manifest.yaml";
const SIGNATURE_NAME: &str = "signature.yaml";
const UNSQUASHFS: &str = "unsquashfs";

pub(crate) fn inspect(npk: &Path, short: bool) -> Result<()> {
    if short {
        inspect_short(npk)
    } else {
        inspect_long(npk)
    }
}

fn inspect_short(npk: &Path) -> Result<()> {
    let npk = Npk::<BufReader<File>>::from_path(npk, None)?;
    let manifest = npk.manifest();
    let npk_version = &npk.metadata().npk_version;
    let mut info = vec![manifest.container().to_string()];
    info.push(format!("NPK version: {}", npk_version));
    info.push(format!("Build date: {}", npk.metadata().date));
    if let Some(author) = &npk.metadata().author {
        info.push(format!("Author: {}", author));
    }
    println!("{}", info.join(", "));

    Ok(())
}

fn inspect_long(npk: &Path) -> Result<()> {
    let mut zip = open(npk)?;
    let mut print_buf: String = String::new();
    println!(
        "{}",
        format!("# inspection of '{}'", &npk.display()).green()
    );
    println!("{}", "## NPK Content".to_string().green());
    zip.file_names().for_each(|f| println!("{}", f));
    println!();

    // print manifest
    let mut man = zip
        .by_name(MANIFEST_NAME)
        .context("failed to find manifest in NPK")?;
    println!("{}", format!("## {}", MANIFEST_NAME).green());
    man.read_to_string(&mut print_buf)
        .with_context(|| "failed to read manifest")?;
    println!("{}", &print_buf);
    print!("\n\n");
    print_buf.clear();
    drop(man);

    // print signature
    match zip.by_name(SIGNATURE_NAME) {
        Ok(mut sig) => {
            println!("{}", format!("## {}", SIGNATURE_NAME).green());
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
    print_squashfs(path)?;

    Ok(())
}

fn print_squashfs(fsimg_path: &Path) -> Result<()> {
    which::which(&UNSQUASHFS).with_context(|| anyhow!("failed to find '{}'", &UNSQUASHFS))?;

    let mut cmd = Command::new(&UNSQUASHFS);
    cmd.arg("-ll").arg(fsimg_path.display().to_string());

    let output = cmd
        .output()
        .with_context(|| format!("failed to execute '{}'", &UNSQUASHFS))?;

    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}

#[cfg(test)]
mod test {
    use super::inspect;
    use northstar::npk::npk::{generate_key, pack, SquashfsOpts};
    use std::{
        fs::File,
        io::Write,
        path::{Path, PathBuf},
    };
    use tempfile::TempDir;

    const TEST_KEY_NAME: &str = "test_key";
    const TEST_MANIFEST: &str = "name: hello
version: 0.0.1
init: /hello
uid: 1000
gid: 1000";

    fn create_test_npk(dest: &Path) -> PathBuf {
        let src = create_tmp_dir();
        let key_dir = create_tmp_dir();
        let manifest = create_test_manifest(src.path());
        let (_pub_key, prv_key) = gen_test_key(key_dir.path());
        let dest = dest.join("hello:0.0.1.npk");
        pack(
            &manifest,
            src.path(),
            &dest,
            SquashfsOpts::default(),
            Some(&prv_key),
            None,
        )
        .expect("failed to pack NPK");
        dest
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
        generate_key(TEST_KEY_NAME, key_dir).expect("generate key pair");
        let prv_key = key_dir.join(&TEST_KEY_NAME).with_extension("key");
        let pub_key = key_dir.join(&TEST_KEY_NAME).with_extension("pub");
        assert!(prv_key.exists());
        assert!(pub_key.exists());
        (pub_key, prv_key)
    }

    #[test]
    fn inspect_npk() {
        let dest = create_tmp_dir();
        let npk = create_test_npk(dest.path());
        assert!(npk.exists());
        inspect(&npk, true).expect("inspect NPK");
        inspect(&npk, false).expect("inspect NPK");
    }

    #[test]
    fn inspect_npk_no_file() {
        inspect(Path::new("invalid"), true).expect_err("invalid NPK");
        inspect(Path::new("invalid"), false).expect_err("invalid NPK");
    }
}
