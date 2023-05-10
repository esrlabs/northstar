use std::{
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path},
};

use anyhow::Context;
use lazy_static::lazy_static;
use northstar_runtime::npk::{
    manifest::Manifest,
    npk::{self, Compression, SquashfsOptions},
};
use tempfile::tempdir;

macro_rules! npk {
    ($x:expr) => {{
        fs::File::open($x)
            .and_then(|file| file.metadata().map(|m| m.size()).map(|m| (file, m)))
            .and_then(|(mut file, size)| {
                let mut data = Vec::with_capacity(size as usize);
                file.read_to_end(&mut data).map(|_| data)
            })
            .expect(&format!(
                "failed to read {}. Have you build the examples?",
                $x
            ))
    }};
}

pub const EXAMPLE_CONSOLE: &str = "console:0.0.1";
pub const EXAMPLE_CPUEATER: &str = "cpueater:0.0.1";
pub const EXAMPLE_CRASHING: &str = "crashing:0.0.1";
pub const EXAMPLE_FERRIS: &str = "ferris:0.0.1";
pub const EXAMPLE_HELLO_FERRIS: &str = "hello-ferris:0.0.1";
pub const EXAMPLE_HELLO_RESOURCE: &str = "hello-resource:0.0.1";
pub const EXAMPLE_INSPECT: &str = "inspect:0.0.1";
pub const EXAMPLE_MEMEATER: &str = "memeater:0.0.1";
pub const EXAMPLE_MESSAGE_0_0_1: &str = "message:0.0.1";
pub const EXAMPLE_MESSAGE_0_0_2: &str = "message:0.0.2";
pub const EXAMPLE_NETNS: &str = "netns:0.0.1";
pub const EXAMPLE_PERSISTENCE: &str = "persistence:0.0.1";
pub const EXAMPLE_REDIS: &str = "redis:0.0.1";
pub const EXAMPLE_REDIS_CLIENT: &str = "redis-client:0.0.1";
pub const EXAMPLE_SECCOMP: &str = "seccomp:0.0.1";
pub const EXAMPLE_SOCKETS: &str = "sockets:0.0.1";
pub const EXAMPLE_TOKEN_CLIENT: &str = "token-client:0.0.1";
pub const EXAMPLE_TOKEN_SERVER: &str = "token-server:0.0.1";
pub const TEST_CONTAINER: &str = "test-container:0.0.1";
pub const TEST_RESOURCE: &str = "test-resource:0.0.1";

lazy_static! {
    pub static ref EXAMPLE_CONSOLE_NPK: Vec<u8> =
        npk!("../target/northstar/repository/console-0.0.1.npk");
    pub static ref EXAMPLE_CPUEATER_NPK: Vec<u8> =
        npk!("../target/northstar/repository/cpueater-0.0.1.npk");
    pub static ref EXAMPLE_CRASHING_NPK: Vec<u8> =
        npk!("../target/northstar/repository/crashing-0.0.1.npk");
    pub static ref EXAMPLE_FERRIS_NPK: Vec<u8> =
        npk!("../target/northstar/repository/ferris-0.0.1.npk");
    pub static ref EXAMPLE_HELLO_FERRIS_NPK: Vec<u8> =
        npk!("../target/northstar/repository/hello-ferris-0.0.1.npk");
    pub static ref EXAMPLE_HELLO_RESOURCE_NPK: Vec<u8> =
        npk!("../target/northstar/repository/hello-resource-0.0.1.npk");
    pub static ref EXAMPLE_INSPECT_NPK: Vec<u8> =
        npk!("../target/northstar/repository/inspect-0.0.1.npk");
    pub static ref EXAMPLE_NETNS_NPK: Vec<u8> =
        npk!("../target/northstar/repository/netns-0.0.1.npk");
    pub static ref EXAMPLE_MEMEATER_NPK: Vec<u8> =
        npk!("../target/northstar/repository/memeater-0.0.1.npk");
    pub static ref EXAMPLE_MESSAGE_0_0_1_NPK: Vec<u8> =
        npk!("../target/northstar/repository/message-0.0.1.npk");
    pub static ref EXAMPLE_MESSAGE_0_0_2_NPK: Vec<u8> =
        npk!("../target/northstar/repository/message-0.0.2.npk");
    pub static ref EXAMPLE_PERSISTENCE_NPK: Vec<u8> =
        npk!("../target/northstar/repository/persistence-0.0.1.npk");
    pub static ref EXAMPLE_REDIS_NPK: Vec<u8> =
        npk!("../target/northstar/repository/redis-0.0.1.npk");
    pub static ref EXAMPLE_REDIS_CLIENT_NPK: Vec<u8> =
        npk!("../target/northstar/repository/redis-client-0.0.1.npk");
    pub static ref EXAMPLE_SECCOMP_NPK: Vec<u8> =
        npk!("../target/northstar/repository/seccomp-0.0.1.npk");
    pub static ref EXAMPLE_SOCKETS_NPK: Vec<u8> =
        npk!("../target/northstar/repository/sockets-0.0.1.npk");
    pub static ref EXAMPLE_TOKEN_CLIENT_NPK: Vec<u8> =
        npk!("../target/northstar/repository/token-client-0.0.1.npk");
    pub static ref EXAMPLE_TOKEN_SERVER_NPK: Vec<u8> =
        npk!("../target/northstar/repository/token-server-0.0.1.npk");
    pub static ref TEST_CONTAINER_NPK: Vec<u8> =
        npk!("../target/northstar/repository/test-container-0.0.1.npk");
    pub static ref TEST_RESOURCE_NPK: Vec<u8> =
        npk!("../target/northstar/repository/test-resource-0.0.1.npk");
}

/// Apply manifest patch function `patch` to manifest of `container`. Returns the repacked container.
pub fn with_manifest<F>(container: &[u8], patch: F) -> anyhow::Result<Vec<u8>>
where
    F: FnOnce(&mut Manifest),
{
    let tmpdir = tempdir()?;
    let key = Path::new("../examples/northstar.key");
    let src = tmpdir.path().join("src.npk");
    let unpacked = tmpdir.path().join("unpacked");
    let manifest = unpacked.join("manifest.yaml");
    let out = tmpdir.path().join("out.npk");
    let root = unpacked.join("squashfs-root");

    // Dump container to disk and unpack it.
    fs::write(&src, container)?;
    npk::unpack(&src, &unpacked)?;

    // Load manifest
    let manifest = fs::File::open(&manifest).context("failed to open manifest")?;
    let mut manifest = Manifest::from_reader(manifest).context("failed to parse manifest")?;

    // Remove existing mountpoints that are created while packing.
    for mount_point in manifest.mounts.keys() {
        let mount_point = tmpdir
            .path()
            .join(mount_point.strip_prefix("/").unwrap_or(mount_point));
        fs::remove_dir_all(mount_point).ok();
    }

    // Apply manifest patch.
    patch(&mut manifest);

    // Repack
    npk::pack_with_manifest(
        &manifest,
        &root,
        &out,
        Some(key),
        &SquashfsOptions {
            compression: Compression::Gzip,
            ..Default::default()
        },
    )
    .context("failed to pack")?;

    // Load repacked container.
    let mut buf = Vec::new();
    fs::File::open(&out)
        .context("failed to open npk")?
        .read_to_end(&mut buf)
        .context("failed to read npk")
        .map(|_| buf)
}
