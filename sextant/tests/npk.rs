// Copyright (c) 2020 ESRLabs
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

#[cfg(test)]
mod npk {
    use sextant::npk::{gen_key, inspect, pack, unpack};
    use std::{
        fs::File,
        io::{Read, Write},
        path::{Path, PathBuf},
    };

    const TEST_KEY_NAME: &str = "test_key";
    const TEST_MANIFEST: &str = "name: hello
version: 0.0.2
init: /hello
env:
  HELLO: north
# autostart: true
# instances: 20
mounts:
    /lib:
      host: /lib
    /lib64:
      host: /lib64
    /system:
      host: /system";
    const TEST_MANIFEST_UNPACKED: &str = "---
name: hello
version: 0.0.2
init: /hello
env:
  HELLO: north
mounts:
  /lib:
    host: /lib
    flags: []
  /lib64:
    host: /lib64
    flags: []
  /system:
    host: /system
    flags: []";

    fn create_test_npk(dest: &Path) -> PathBuf {
        let src = create_tmp_dir();
        let key_dir = create_tmp_dir();
        create_test_manifest(&src);
        let (_pub_key, prv_key) = gen_test_key(&key_dir);
        pack(&src, &dest, &prv_key).expect("Pack NPK");
        dest.join("hello-0.0.2.npk")
    }

    fn create_test_manifest(src: &PathBuf) -> PathBuf {
        let manifest = src.join("manifest").with_extension("yaml");
        File::create(&manifest)
            .expect("Create manifest.yaml")
            .write_all(TEST_MANIFEST.as_ref())
            .expect("Write test manifest");
        manifest
    }

    fn create_tmp_dir() -> PathBuf {
        tempfile::TempDir::new()
            .expect("Create tmp dir")
            .into_path()
    }

    fn gen_test_key(key_dir: &Path) -> (PathBuf, PathBuf) {
        gen_key(&TEST_KEY_NAME, &key_dir).expect("Generate key pair");
        let prv_key = key_dir.join(&TEST_KEY_NAME).with_extension("key");
        let pub_key = key_dir.join(&TEST_KEY_NAME).with_extension("pub");
        assert!(prv_key.exists());
        assert!(pub_key.exists());
        (pub_key, prv_key)
    }

    #[cfg(not(target_os = "macos"))] // no 'mksquashfs' binary available on CI
    #[test]
    fn pack_npk() {
        create_test_npk(&create_tmp_dir());
    }

    #[test]
    fn pack_npk_no_manifest() {
        let key_dir = create_tmp_dir();
        let (_pub_key, prv_key) = gen_test_key(&key_dir);
        pack(Path::new("invalid"), &create_tmp_dir(), &prv_key).expect_err("Invalid manifest");
    }

    #[test]
    fn pack_npk_no_dest() {
        let src = create_tmp_dir();
        let key_dir = create_tmp_dir();
        create_test_manifest(&src);
        let (_pub_key, prv_key) = gen_test_key(&key_dir);
        pack(&src, &Path::new("invalid"), &prv_key).expect_err("Invalid destination dir");
    }

    #[test]
    fn pack_npk_no_keys() {
        let src = create_tmp_dir();
        create_test_manifest(&src);
        pack(&src, &create_tmp_dir(), &Path::new("invalid")).expect_err("Invalid key dir");
    }

    #[cfg(not(target_os = "macos"))] // no 'mksquashfs' binary available on CI
    #[test]
    fn unpack_npk() {
        let npk = create_test_npk(&create_tmp_dir());
        assert!(npk.exists());
        let unpack_dest = create_tmp_dir();
        unpack(&npk, &unpack_dest).expect("Unpack NPK");
        let manifest_path = unpack_dest.join("manifest").with_extension("yaml");
        assert!(manifest_path.exists());
        let mut manifest: String = "".to_string();
        File::open(manifest_path)
            .expect("Open unpacked manifest")
            .read_to_string(&mut manifest)
            .expect("Read unpacked manifest");
        assert_eq!(TEST_MANIFEST_UNPACKED, manifest);
    }

    #[cfg(not(target_os = "macos"))] // no 'mksquashfs' binary available on CI
    #[test]
    fn inspect_npk() {
        let npk = create_test_npk(&create_tmp_dir());
        assert!(npk.exists());
        inspect(&npk).expect("Inspect NPK");
    }

    #[test]
    fn inspect_npk_no_file() {
        inspect(&Path::new("invalid")).expect_err("Invalid NPK");
    }

    #[test]
    fn gen_key_pair() {
        gen_test_key(&create_tmp_dir());
    }

    #[test]
    fn gen_key_pair_no_dest() {
        gen_key(&TEST_KEY_NAME, &Path::new("invalid")).expect_err("Invalid key dir");
    }

    #[test]
    fn do_not_overwrite_keys() -> Result<(), anyhow::Error> {
        let tmp = create_tmp_dir();
        gen_key(&TEST_KEY_NAME, &tmp).expect("Generate keys");
        gen_key(&TEST_KEY_NAME, &tmp).expect_err("Cannot overwrite keys");
        Ok(())
    }
}
