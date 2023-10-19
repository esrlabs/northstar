use super::mount::{Bind, Mount, MountOption, Resource, Tmpfs};
use crate::{common::version::VersionReq, npk::manifest::*, seccomp::SyscallRule};
use anyhow::Result;
use std::{
    convert::{TryFrom, TryInto},
    iter::FromIterator,
};

fn nn(s: &str) -> NonNulString {
    unsafe { NonNulString::from_str_unchecked(s) }
}

#[test]
fn parse() -> Result<()> {
    let manifest = "
name: hello
version: 0.0.0
init: /binary
args:
  - one
  - two
env:
  LD_LIBRARY_PATH: /lib
uid: 1000
gid: 1001
sched:
  policy:
    !other
      nice: 10
suppl_groups:
  - inet
  - log
capabilities:
  - CAP_NET_RAW
  - CAP_MKNOD
  - CAP_SYS_TIME
rlimits:
  nproc:
    soft: 1000
    hard: 1000
mounts:
  /dev:
    type: dev
  /tmp:
    type: tmpfs
    size: 42
  /lib:
    type: bind
    host: /lib
    options: rw
  /data:
    type: persist
  /resource:
    type: resource
    name: bla-blah.foo
    version: '>=1.0.0'
    dir: /bin/foo
    options: noexec
autostart: critical
seccomp:
  allow:
    fork: any
    waitpid: any
sockets:
  foo:
    type: stream
    mode: 0o600
    uid: 100
    gid: 1000
  bar:
    type: datagram
    mode: 0o600
    uid: 100
    gid: 1000
  baz:
    type: seq_packet
    mode: 0o600
    uid: 100
    gid: 1000
cgroups:
  memory:
    oom_monitor: true
    memory_hard_limit: 1000000
    memory_soft_limit: 1000000
    swappiness: 0
    attrs: {}
  cpu:
    cpus: 0,1
    shares: 1024
    attrs: {}
";

    let manifest = Manifest::from_str(manifest)?;

    assert_eq!(manifest.init, NonNulString::try_from("/binary").ok());
    assert_eq!(manifest.name.to_string(), "hello");
    assert_eq!(manifest.args.len(), 2);
    assert_eq!(manifest.args[0].to_string(), "one");
    assert_eq!(manifest.args[1].to_string(), "two");

    assert_eq!(manifest.autostart, Some(autostart::Autostart::Critical));
    assert_eq!(
        manifest.env.get(&"LD_LIBRARY_PATH".try_into()?),
        Some("/lib".try_into()?).as_ref()
    );
    assert_eq!(manifest.uid, 1000);
    assert_eq!(manifest.gid, 1001);
    let mut mounts = HashMap::new();
    mounts.insert(
        nn("/lib"),
        Mount::Bind(Bind {
            host: nn("/lib"),
            options: [MountOption::Rw].iter().cloned().collect(),
        }),
    );
    mounts.insert(nn("/data"), Mount::Persist);
    mounts.insert(
        nn("/resource"),
        Mount::Resource(Resource {
            name: "bla-blah.foo".try_into()?,
            version: VersionReq::parse(">=1.0.0")?,
            dir: unsafe { NonNulString::from_str_unchecked("/bin/foo") },
            options: [MountOption::NoExec].iter().cloned().collect(),
        }),
    );
    mounts.insert(nn("/tmp"), Mount::Tmpfs(Tmpfs { size: 42 }));
    mounts.insert(nn("/dev"), Mount::Dev);
    assert_eq!(manifest.mounts, mounts);

    let mut syscalls: HashMap<NonNulString, SyscallRule> = HashMap::new();
    syscalls.insert(
        NonNulString::try_from("fork".to_string())?,
        SyscallRule::Any,
    );
    syscalls.insert(
        NonNulString::try_from("waitpid".to_string())?,
        SyscallRule::Any,
    );
    assert_eq!(
        manifest.seccomp,
        Some(Seccomp {
            profile: None,
            allow: Some(syscalls)
        })
    );

    assert_eq!(
        manifest.capabilities,
        HashSet::from_iter(
            vec!(
                capabilities::Capability::CAP_NET_RAW,
                capabilities::Capability::CAP_MKNOD,
                capabilities::Capability::CAP_SYS_TIME,
            )
            .drain(..)
        )
    );
    let suppl_groups = unsafe {
        ["inet", "log"]
            .into_iter()
            .map(|s| NonNulString::from_str_unchecked(s))
            .collect()
    };
    assert_eq!(manifest.suppl_groups, suppl_groups);

    Ok(())
}

/// Invalid init too short.
#[test]
fn invalid_init_too_short() -> Result<()> {
    let manifest = "name: hello\nversion: 0.0.0\ninit: \"\"\nuid: 1\ngid: 1001";
    assert!(Manifest::from_str(manifest).is_err());
    Ok(())
}

/// Invalid init too long.
#[test]
fn invalid_init_too_long() -> Result<()> {
    let manifest = format!(
        "name: hello\nversion: 0.0.0\ninit: {}\nuid: 1\ngid: 1001",
        "b".repeat(4097)
    );

    assert!(dbg!(Manifest::from_str(&manifest)).is_err());
    Ok(())
}

/// Invalid uid
#[test]
fn invalid_uid_zero() -> Result<()> {
    let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 0\ngid: 1001";
    assert!(Manifest::from_str(manifest).is_err());
    Ok(())
}

/// Invalid gid
#[test]
fn invalid_gid_zero() -> Result<()> {
    let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1\ngid: 0";
    assert!(Manifest::from_str(manifest).is_err());
    Ok(())
}

/// Invalid selinux context
#[test]
fn invalid_selinux_context() -> Result<()> {
    let manifest =
        "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1\ngid: 1\nselinux:\n    mount_context: fo@o";
    assert!(Manifest::from_str(manifest).is_err());
    Ok(())
}

/// Invalid suppl group with nul byte
#[test]
fn invalid_suppl_group_nul() -> Result<()> {
    let manifest =
        "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1\ngid: 1\nsuppl_groups: [fo\0o]";
    assert!(Manifest::from_str(manifest).is_err());
    Ok(())
}

/// Invalid too long suppl group
#[test]
fn invalid_suppl_group_too_long() -> Result<()> {
    let manifest =
            "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1\ngid: 1\nsuppl_groups: [looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong]";
    assert!(Manifest::from_str(manifest).is_err());
    Ok(())
}

/// Too many suppl groups
#[test]
fn invalid_suppl_group_duplicate() -> Result<()> {
    let manifest =
        "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1\ngid: 1\nsuppl_groups: [foo, foo]";
    assert!(Manifest::from_str(manifest).is_err());
    Ok(())
}

/// Two mounts on the same target are invalid
#[test]
fn duplicate_mount() -> Result<()> {
    let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
mounts:
  /dev:
    type: dev
  /dev:
    type: dev
";
    assert!(Manifest::from_str(manifest).is_err());
    Ok(())
}

/// Overlapping mounts are invalid
#[test]
fn overlapping_mount() -> Result<()> {
    let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
mounts:
  /lib/overlapping:
    type: bind
    host: /lib
  /lib/non_overlapping1:
    type: bind
    host: /lib
  /lib/non_overlapping2:
    type: bind
    host: /lib
  /lib/overlapping/foo:
    type: bind
    host: /lib
";
    assert!(Manifest::from_str(manifest).is_err());
    Ok(())
}

/// Non-overlapping mounts are invalid
#[test]
fn non_overlapping_mount() -> Result<()> {
    let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
mounts:
  /other_lib1:
    type: bind
    host: /lib
  /lib/non_overlapping1:
    type: bind
    host: /lib
  /other_lib2:
    type: bind
    host: /lib
  /lib/non_overlapping2:
    type: bind
    host: /lib
";
    assert!(Manifest::from_str(manifest).is_ok());
    Ok(())
}

/// Resource mount with realtive dir
#[test]
#[should_panic]
fn resource_relative_dir() {
    let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
mounts:
  /resource:
    type: resource
    name: bla-blah.foo
    version: '>=1.0.0'
    dir: bin/foo
";
    Manifest::from_str(manifest).expect("failed to parse manifest");
}

/// Resource mount with absolute dir
#[test]
fn resource_absolute() {
    let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
mounts:
  /resource:
    type: resource
    name: bla-blah.foo
    version: '>=1.0.0'
    dir: /bin/foo
";
    Manifest::from_str(manifest).expect("failed to parse manifest");
}

#[test]
fn tmpfs() {
    let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
mounts:
  /a:
    type: tmpfs
    size: 100
  /b:
    type: tmpfs
    size: 100kB
  /c:
    type: tmpfs
    size: 100MB
  /d:
    type: tmpfs
    size: 100GB
";
    let mountpoint = |s| -> NonNulString { unsafe { NonNulString::from_str_unchecked(s) } };
    let manifest = Manifest::from_str(manifest).expect("failed to parse manifest");
    assert_eq!(
        manifest.mounts.get(&mountpoint("/a")),
        Some(&Mount::Tmpfs(Tmpfs { size: 100 }))
    );
    assert_eq!(
        manifest.mounts.get(&mountpoint("/b")),
        Some(&Mount::Tmpfs(Tmpfs { size: 100000 }))
    );
    assert_eq!(
        manifest.mounts.get(&mountpoint("/c")),
        Some(&Mount::Tmpfs(Tmpfs { size: 100000000 }))
    );
    assert_eq!(
        manifest.mounts.get(&mountpoint("/d")),
        Some(&Mount::Tmpfs(Tmpfs { size: 100000000000 }))
    );

    // Test a invalid tmpfs size string
    let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\n uid: 1000\ngid: 1001
mounts:
  /tmp:
    type: tmpfs
    size: 100MB
";
    assert!(Manifest::from_str(manifest).is_err());
}

#[test]
fn dev_minimal() {
    let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001\nmounts:\n  /dev:\n    type: dev";
    assert!(Manifest::from_str(manifest).is_ok());
}

#[test]
fn mount_resource() {
    let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001
mounts:
  /foo:
    type: resource
    name: foo-bar.qwerty12
    version: '>=0.0.1'
    dir: /
    options: rw,noexec,nosuid
";
    Manifest::from_str(manifest).expect("failed to parse manifest");
}

const ROUNDTRIP_MANIFEST: &str = "
name: hello
version: 0.0.0
init: /binary
uid: 1000
gid: 1001
console:
  permissions: full
args:
  - one
  - two
env:
  LD_LIBRARY_PATH: /lib
sched:
  policy: idle
mounts:
  /dev:
    type: dev
  /lib:
    type: bind
    host: /lib
    options: rw,nosuid,nodev,noexec
  /no_option:
    type: bind
    host: /foo
  /data:
    type: persist
  /resource:
    type: resource
    name: bla-bar.blah1234
    version: '>=1.0.0'
    dir: /bin/foo
    options: rw,nosuid,nodev,noexec
autostart: relaxed
seccomp:
  allow:
    fork: any
    waitpid: any
capabilities:
  - CAP_NET_ADMIN
io:
  stdout: pipe
  stderr: pipe
cgroups:
    memory:
      memory_hard_limit: 1000000
      memory_soft_limit: 1000000
      swappiness: 0
      attrs: {}
    cpu:
      cpus: 0,1
      shares: 1024
      attrs: {}
custom:
    blah: foo
    foo: 234
    test:
      - one
      - two
      - three
";

#[test]
fn roundtrip_yaml() -> Result<()> {
    let manifest = serde_yaml::from_str::<Manifest>(ROUNDTRIP_MANIFEST)?;
    let yaml = serde_yaml::to_string(&manifest)?;
    let deserialized = serde_yaml::from_str::<Manifest>(&yaml)?;
    assert_eq!(manifest, deserialized);

    Ok(())
}

#[test]
fn roundtrip_toml() -> Result<()> {
    let manifest = serde_yaml::from_str::<Manifest>(ROUNDTRIP_MANIFEST)?;
    manifest.validate()?;
    let toml_value = toml::Value::try_from(&manifest)?;
    let toml = toml::to_string(&toml_value)?;
    println!("{toml}");
    let deserialized = toml::from_str::<Manifest>(&toml)?;
    deserialized.validate()?;
    assert_eq!(manifest, deserialized);
    Ok(())
}

#[test]
fn roundtrip_json() -> Result<()> {
    let manifest = serde_yaml::from_str::<Manifest>(ROUNDTRIP_MANIFEST)?;
    manifest.validate()?;
    let json = serde_json::to_string(&manifest)?;
    let deserialized = serde_json::from_str::<Manifest>(&json)?;
    deserialized.validate()?;
    assert_eq!(manifest, deserialized);
    Ok(())
}

/// Check reserved env keys
#[test]
fn env() -> Result<()> {
    let manifest = "name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001\n
env:
  LD_LIBRARY_PATH: /lib
  PATH: /bin";

    assert!(Manifest::from_str(manifest).is_ok());

    let manifest = r"name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001\n
env:
  NORTHSTAR_CONSOLE: foo";
    assert!(Manifest::from_str(manifest).is_err());

    let manifest = r"name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001\n
env:
  NORTHSTAR_NAME: foo";
    assert!(Manifest::from_str(manifest).is_err());

    let manifest = r"name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001\n
env:
  NORTHSTAR_CONTAINER: foo";
    assert!(Manifest::from_str(manifest).is_err());

    let manifest = r"name: hello\nversion: 0.0.0\ninit: /binary\nuid: 1000\ngid: 1001\n
env:
  NORTHSTAR_VERSION: foo";
    assert!(Manifest::from_str(manifest).is_err());
    Ok(())
}
