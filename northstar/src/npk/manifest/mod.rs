use crate::{
    common::{container::Container, name::Name, non_nul_string::NonNulString, version::Version},
    seccomp::{Seccomp, Selinux, SyscallRule},
};
use itertools::Itertools;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{rust::maps_duplicate_key_is_error, skip_serializing_none};
use std::{
    collections::{HashMap, HashSet},
    io,
    path::{Component, Component::RootDir, PathBuf},
    str::FromStr,
};
use thiserror::Error;

pub use cgroups::*;
pub use console::*;
pub use mount::*;

mod cgroups;
mod console;
mod mount;

/// Northstar package manifest
#[skip_serializing_none]
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Name of container
    pub name: Name,
    /// Container version
    pub version: Version,
    /// Pass a console fd number in NORTHSTAR_CONSOLE
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub console: Console,
    /// Path to init
    pub init: Option<PathBuf>,
    /// Additional arguments for the application invocation
    pub args: Option<Vec<NonNulString>>,
    /// UID
    pub uid: u16,
    /// GID
    pub gid: u16,
    /// List of bind mounts and resources
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    #[serde(deserialize_with = "maps_duplicate_key_is_error::deserialize")]
    pub mounts: HashMap<PathBuf, Mount>,
    /// Environment passed to container
    pub env: Option<HashMap<NonNulString, NonNulString>>,
    /// Autostart this container upon northstar startup
    pub autostart: Option<Autostart>,
    /// CGroup configuration
    pub cgroups: Option<cgroups::CGroups>,
    /// Seccomp configuration
    pub seccomp: Option<Seccomp>,
    /// SELinux configuration
    pub selinux: Option<Selinux>,
    /// Capabilities
    pub capabilities: Option<HashSet<Capability>>,
    /// String containing group names to give to new container
    pub suppl_groups: Option<Vec<NonNulString>>,
    /// Resource limits
    pub rlimits: Option<HashMap<RLimitResource, RLimitValue>>,
    /// IO configuration
    #[serde(default, skip_serializing_if = "is_default")]
    pub io: Io,
    /// Optional custom data. The runtime doesnt use this.
    pub custom: Option<Value>,
}

impl Manifest {
    /// Manifest version supported by the runtime
    pub const VERSION: Version = Version::new(0, 1, 0);

    /// Container that is specified in the manifest
    pub fn container(&self) -> Container {
        Container::new(self.name.clone(), self.version.clone())
    }

    /// Read a manifest from `reader`
    pub fn from_reader<R: io::Read>(reader: R) -> Result<Self, Error> {
        let manifest: Self = serde_yaml::from_reader(reader).map_err(Error::SerdeYaml)?;
        manifest.verify()?;
        Ok(manifest)
    }

    /// Write the manifest to `writer`
    pub fn to_writer<W: io::Write>(&self, writer: W) -> Result<(), Error> {
        serde_yaml::to_writer(writer, self).map_err(Error::SerdeYaml)
    }

    fn verify(&self) -> Result<(), Error> {
        // Most optionals in the manifest are not valid for a resource container

        if let Some(init) = &self.init {
            if NonNulString::try_from(init.display().to_string()).is_err() {
                return Err(Error::Invalid(
                    "init path must be a string without zero bytes".to_string(),
                ));
            }
        } else if self.args.is_some()
            || self.env.is_some()
            || self.autostart.is_some()
            || self.cgroups.is_some()
            || self.seccomp.is_some()
            || self.capabilities.is_some()
            || self.suppl_groups.is_some()
        {
            return Err(Error::Invalid(
                "resource containers must not define any of the following manifest entries:\
                    args, env, autostart, cgroups, seccomp, capabilities, suppl_groups, io"
                    .to_string(),
            ));
        }

        // Check for invalid uid or gid of 0
        if self.uid == 0 {
            return Err(Error::Invalid("invalid uid of 0".to_string()));
        }
        if self.gid == 0 {
            return Err(Error::Invalid("invalid gid of 0".to_string()));
        }

        // Check for reserved env variable names
        if let Some(env) = &self.env {
            for name in ["NAME", "VERSION", "NORTHSTAR_CONSOLE"] {
                if env.keys().any(|k| name == k.as_str()) {
                    return Err(Error::Invalid(format!(
                        "invalid env: resevered variable {}",
                        name
                    )));
                }
            }
        }

        // Check for relative and overlapping bind mounts
        let mut prev_comps = vec![RootDir];
        self.mounts
            .iter()
            .filter(|(_, m)| matches!(m, Mount::Bind(_)))
            .map(|(p, _)| p)
            .sorted()
            .try_for_each(|p| {
                if p.is_relative() {
                    return Err(Error::Invalid(
                        "mount points must not be relative".to_string(),
                    ));
                }
                // Check for overlapping bind mount paths by checking if one path is the prefix of the next one
                let curr_comps: Vec<Component> = p.components().into_iter().collect();
                let prev_too_short = prev_comps.len() <= 1; // Two mount paths both starting with '/' is not considered an overlap
                let prev_too_long = prev_comps.len() > curr_comps.len(); // A longer path cannot be the prefix of a shorter one

                if !prev_too_short && !prev_too_long && prev_comps == curr_comps[..prev_comps.len()]
                {
                    return Err(Error::Invalid("mount points must not overlap".to_string()));
                }
                prev_comps = curr_comps;
                Ok(())
            })?;

        // Check for recursive non bind mounts
        self.mounts
            .iter()
            .map(|(_, m)| m)
            .try_for_each(|m| match m {
                // The options field, which must be checked, is available for Mount::Bind and Mount::Resource
                Mount::Resource(m) => {
                    if m.options.contains(&MountOption::Rec) {
                        Err(Error::Invalid(
                            "non bind mounts must not be recursive".to_string(),
                        ))
                    } else {
                        Ok(())
                    }
                }
                _ => Ok(()),
            })?;

        // Check selinux context
        if let Some(selinux) = &self.selinux {
            // Maximum length since at least Linux v3.7
            // (https://elixir.bootlin.com/linux/v3.7/source/include/uapi/linux/limits.h)
            const XATTR_SIZE_MAX: usize = 65536;

            if selinux.context.len() >= XATTR_SIZE_MAX {
                return Err(Error::Invalid(format!(
                    "Selinux context os too long. Maximum length in {}",
                    XATTR_SIZE_MAX
                )));
            }
            if !selinux
                .context
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '_')
            {
                return Err(Error::Invalid(
                    "Selinux context must consist of alphanumeric ASCII characters, '?' or '_'"
                        .to_string(),
                ));
            }
        }

        // Check seccomp filter
        const MAX_ARG_INDEX: usize = 5; // Restricted by seccomp_data struct
        const MAX_ARG_VALUES: usize = 50; // BPF jumps cannot exceed 255 and each check needs multiple instructions
        if let Some(seccomp) = &self.seccomp {
            if let Some(allowlist) = &seccomp.allow {
                for filter in allowlist {
                    match filter.1 {
                        SyscallRule::Args(args) => {
                            if args.index > MAX_ARG_INDEX {
                                return Err(Error::Invalid(format!(
                                    "Seccomp syscall argument index must be {} or less",
                                    MAX_ARG_INDEX
                                )));
                            }
                            if args.values.is_none() && args.mask.is_none() {
                                return Err(Error::Invalid(
                                    "Either 'values' or 'mask' must be defined in seccomp syscall argument filter".to_string()));
                            }
                            if let Some(values) = &args.values {
                                if values.len() > MAX_ARG_VALUES {
                                    return Err(Error::Invalid(format!(
                                        "Seccomp syscall argument cannot have more than {} allowed values",
                                        MAX_ARG_VALUES)));
                                }
                            }
                        }
                        SyscallRule::Any => {
                            // This syscall is allowed unconditionally
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl FromStr for Manifest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Manifest, Error> {
        let manifest: Self = serde_yaml::from_str(s).map_err(Error::SerdeYaml)?;
        manifest.verify()?;
        Ok(manifest)
    }
}

impl ToString for Manifest {
    fn to_string(&self) -> String {
        // A `Manifest` is convertible to `String` as long as its implementation of `Serialize` does
        // not return an error. This should never happen for the types that we use in `Manifest` so
        // we can safely use .unwrap() here.
        serde_yaml::to_string(self).unwrap()
    }
}

/// Manifest parsing error
#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum Error {
    #[error("invalid manifest: {0}")]
    Invalid(String),
    #[error("failed to parse: {0}")]
    SerdeYaml(#[from] serde_yaml::Error),
}

/// Autostart options
#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Autostart {
    /// Ignore errors when starting this container. Ignore the containers termination result
    #[serde(rename = "relaxed")]
    Relaxed,
    /// Exit the runtime if starting this containers fails or the container exits with a non zero exit code.
    /// Use this variant to propagate errors with a container to the system above the runtime e.g init.
    #[serde(rename = "critical")]
    Critical,
}

/// IO configuration for stdin, stdout, stderr
#[derive(Default, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Io {
    /// stdout configuration
    pub stdout: Output,
    /// stderr configuration
    pub stderr: Output,
}

/// Io redirection for stdout/stderr
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub enum Output {
    /// Discard output
    #[serde(rename = "discard")]
    Discard,
    /// Forward output to the logging system with level and optional tag
    #[serde(rename = "pipe")]
    Pipe,
}

impl Default for Output {
    fn default() -> Output {
        Output::Discard
    }
}

/// Log level
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// The "error" level.
    #[serde(alias = "ERROR")]
    Error = 1,
    /// The "warn" level.
    ///
    /// Designates hazardous situations.
    #[serde(alias = "WARN")]
    Warn,
    /// The "info" level.
    ///
    /// Designates useful information.
    #[serde(alias = "INFO")]
    Info,
    /// The "debug" level.
    ///
    /// Designates lower priority information.
    #[serde(alias = "DEBUG")]
    Debug,
    /// The "trace" level.
    ///
    /// Designates very low priority, often extremely verbose, information.
    #[serde(alias = "TRACE")]
    Trace,
}

/// Resource limits. See setrlimit(2)
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all(serialize = "lowercase", deserialize = "lowercase"))]
pub enum RLimitResource {
    /// Address space
    AS,
    /// Maximum size of core file
    CORE,
    /// CPU time limit in seconds
    CPU,
    /// The maximum size of the process's data segment (initialized data,
    /// uninitialized data, and heap).
    DATA,
    /// The maximum size of files that the process may create
    FSIZE,
    /// A limit on the combined number of flock(2) locks and fcntl(2) leases that
    /// this process may establish.
    LOCKS,
    /// The maximum number of bytes of memory that may be locked into RAM
    MEMLOCK,
    /// Specifies the limit on the number of bytes that can be allocated for
    /// POSIX message queues for the real user ID of the calling process
    MSGQUEUE,
    /// Specifies a ceiling to which the process's nice value can be raised using
    /// setpriority(2) or nice(2)
    NICE,
    /// Specifies a value one greater than the maximum file descriptor number
    /// that can be opened by this process
    NOFILE,
    /// The maximum number of processes (or, more precisely on Linux, threads)
    /// that can be created for the real user ID of the calling process
    NPROC,
    /// Specifies the limit (in pages) of the process's resident set (the number
    /// of virtual pages resident in RAM)
    RSS,
    /// Specifies a ceiling on the real-time priority that may be set for this
    /// process using sched_setscheduler(2) and sched_setparam(2).
    RTPRIO,
    /// Specifies a limit (in microseconds) on the amount of CPU time that a
    /// process scheduled under a real-time scheduling policy may consume without
    /// making a blocking system call
    #[cfg(not(target_os = "android"))]
    RTTIME,
    /// Specifies the limit on the number of signals that may be queued for the
    /// real user ID of the calling process
    SIGPENDING,
    /// The maximum size of the process stack, in bytes. Upon reaching this
    /// limit, a SIGSEGV signal is generated
    STACK,
}

/// Value for a rlimit setting
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RLimitValue {
    /// Soft limit value for resource. None indicates `unlimited`.
    pub soft: Option<u64>,
    /// Hard limit value for resource. None indicates `unlimited`.
    pub hard: Option<u64>,
}

/// Linux capability
#[derive(Clone, Eq, Hash, PartialEq, Debug, Serialize, Deserialize, JsonSchema)]
#[allow(non_camel_case_types)]
pub enum Capability {
    /// `CAP_CHOWN` (from POSIX)
    CAP_CHOWN,
    /// `CAP_DAC_OVERRIDE` (from POSIX)
    CAP_DAC_OVERRIDE,
    /// `CAP_DAC_READ_SEARCH` (from POSIX)
    CAP_DAC_READ_SEARCH,
    /// `CAP_FOWNER` (from POSIX)
    CAP_FOWNER,
    /// `CAP_FSETID` (from POSIX)
    CAP_FSETID,
    /// `CAP_KILL` (from POSIX)
    CAP_KILL,
    /// `CAP_SETGID` (from POSIX)
    CAP_SETGID,
    /// `CAP_SETUID` (from POSIX)
    CAP_SETUID,
    /// `CAP_SETPCAP` (from Linux)
    CAP_SETPCAP,
    /// `CAP_LINUX_IMMUTABLE` (from Linux)
    CAP_LINUX_IMMUTABLE,
    /// `CAP_NET_BIND_SERVICE` (from Linux)
    CAP_NET_BIND_SERVICE,
    /// `CAP_NET_BROADCAST` (from Linux)
    CAP_NET_BROADCAST,
    /// `CAP_NET_ADMIN` (from Linux)
    CAP_NET_ADMIN,
    /// `CAP_NET_RAW` (from Linux)
    CAP_NET_RAW,
    /// `CAP_IPC_LOCK` (from Linux)
    CAP_IPC_LOCK,
    /// `CAP_IPC_OWNER` (from Linux)
    CAP_IPC_OWNER,
    /// `CAP_SYS_MODULE` (from Linux)
    CAP_SYS_MODULE,
    /// `CAP_SYS_RAWIO` (from Linux)
    CAP_SYS_RAWIO,
    /// `CAP_SYS_CHROOT` (from Linux)
    CAP_SYS_CHROOT,
    /// `CAP_SYS_PTRACE` (from Linux)
    CAP_SYS_PTRACE,
    /// `CAP_SYS_PACCT` (from Linux)
    CAP_SYS_PACCT,
    /// `CAP_SYS_ADMIN` (from Linux)
    CAP_SYS_ADMIN,
    /// `CAP_SYS_BOOT` (from Linux)
    CAP_SYS_BOOT,
    /// `CAP_SYS_NICE` (from Linux)
    CAP_SYS_NICE,
    /// `CAP_SYS_RESOURCE` (from Linux)
    CAP_SYS_RESOURCE,
    /// `CAP_SYS_TIME` (from Linux)
    CAP_SYS_TIME,
    /// `CAP_SYS_TTY_CONFIG` (from Linux)
    CAP_SYS_TTY_CONFIG,
    /// `CAP_SYS_MKNOD` (from Linux, >= 2.4)
    CAP_MKNOD,
    /// `CAP_LEASE` (from Linux, >= 2.4)
    CAP_LEASE,
    /// `CAP_AUDIT_WRITE`
    CAP_AUDIT_WRITE,
    /// `CAP_AUDIT_CONTROL` (from Linux, >= 2.6.11)
    CAP_AUDIT_CONTROL,
    /// `CAP_SETFCAP`
    CAP_SETFCAP,
    /// `CAP_MAC_OVERRIDE`
    CAP_MAC_OVERRIDE,
    /// `CAP_MAC_ADMIN`
    CAP_MAC_ADMIN,
    /// `CAP_SYSLOG` (from Linux, >= 2.6.37)
    CAP_SYSLOG,
    /// `CAP_WAKE_ALARM` (from Linux, >= 3.0)
    CAP_WAKE_ALARM,
    /// `CAP_BLOCK_SUSPEND`
    CAP_BLOCK_SUSPEND,
    /// `CAP_AUDIT_READ` (from Linux, >= 3.16).
    CAP_AUDIT_READ,
    /// `CAP_PERFMON` (from Linux, >= 5.8).
    CAP_PERFMON,
    /// `CAP_BPF` (from Linux, >= 5.8).
    CAP_BPF,
    /// `CAP_CHECKPOINT_RESTORE` (from Linux, >= 5.9).
    CAP_CHECKPOINT_RESTORE,
}

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    t == &T::default()
}

#[cfg(test)]
mod tests {
    use crate::npk::manifest::*;
    use anyhow::{anyhow, Result};
    use std::{
        convert::{TryFrom, TryInto},
        iter::FromIterator,
    };

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
    version: 1.0.0
    dir: /bin/foo
    options: noexec
autostart: critical
seccomp:
  allow:
    fork: any
    waitpid: any
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
";

        let manifest = Manifest::from_str(manifest)?;

        assert_eq!(manifest.init, Some(PathBuf::from("/binary")));
        assert_eq!(manifest.name.to_string(), "hello");
        let args = manifest.args.ok_or_else(|| anyhow!("Missing args"))?;
        assert_eq!(args.len(), 2);
        assert_eq!(args[0].to_string(), "one");
        assert_eq!(args[1].to_string(), "two");

        assert_eq!(manifest.autostart, Some(Autostart::Critical));
        let env = manifest.env.ok_or_else(|| anyhow!("Missing env"))?;
        assert_eq!(
            env.get(&"LD_LIBRARY_PATH".try_into()?),
            Some("/lib".try_into()?).as_ref()
        );
        assert_eq!(manifest.uid, 1000);
        assert_eq!(manifest.gid, 1001);
        let mut mounts = HashMap::new();
        mounts.insert(
            PathBuf::from("/lib"),
            Mount::Bind(Bind {
                host: PathBuf::from("/lib"),
                options: [MountOption::Rw].iter().cloned().collect(),
            }),
        );
        mounts.insert(PathBuf::from("/data"), Mount::Persist);
        mounts.insert(
            PathBuf::from("/resource"),
            Mount::Resource(Resource {
                name: "bla-blah.foo".try_into()?,
                version: Version::parse("1.0.0")?,
                dir: PathBuf::from("/bin/foo"),
                options: [MountOption::NoExec].iter().cloned().collect(),
            }),
        );
        mounts.insert(PathBuf::from("/tmp"), Mount::Tmpfs(Tmpfs { size: 42 }));
        mounts.insert(PathBuf::from("/dev"), Mount::Dev);
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
            Some(HashSet::from_iter(
                vec!(
                    Capability::CAP_NET_RAW,
                    Capability::CAP_MKNOD,
                    Capability::CAP_SYS_TIME,
                )
                .drain(..)
            ))
        );
        assert_eq!(
            manifest.suppl_groups,
            Some(vec!("inet".try_into()?, "log".try_into()?))
        );

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
        let manifest = Manifest::from_str(manifest).unwrap();
        assert_eq!(
            manifest.mounts.get(&PathBuf::from("/a")),
            Some(&Mount::Tmpfs(Tmpfs { size: 100 }))
        );
        assert_eq!(
            manifest.mounts.get(&PathBuf::from("/b")),
            Some(&Mount::Tmpfs(Tmpfs { size: 100000 }))
        );
        assert_eq!(
            manifest.mounts.get(&PathBuf::from("/c")),
            Some(&Mount::Tmpfs(Tmpfs { size: 100000000 }))
        );
        assert_eq!(
            manifest.mounts.get(&PathBuf::from("/d")),
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
    version: 0.0.1
    dir: /
    options: rw,noexec,nosuid
";
        Manifest::from_str(manifest).unwrap();
    }

    #[test]
    fn roundtrip() -> Result<()> {
        let m = "
name: hello
version: 0.0.0
init: /binary
uid: 1000
gid: 1001
console: full
args:
  - one
  - two
env:
  LD_LIBRARY_PATH: /lib
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
    version: 1.0.0
    dir: /bin/foo
    options: rw,nosuid,nodev,noexec
  /tmp:
    type: tmpfs
    size: 42
autostart: relaxed
rlimits:
  nproc:
    soft: 100
    hard: 1000
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

        let manifest = serde_yaml::from_str::<Manifest>(m)?;
        let deserialized = serde_yaml::from_str::<Manifest>(&serde_yaml::to_string(&manifest)?)?;

        assert_eq!(manifest, deserialized);
        Ok(())
    }

    #[test]
    fn version() -> Result<()> {
        let v1 = Version::parse("1.0.0")?;
        let v2 = Version::parse("2.0.0")?;
        let v3 = Version::parse("3.0.0")?;
        assert!(v2 > v1);
        assert!(v2 < v3);
        let v1_1 = Version::parse("1.1.0")?;
        assert!(v1_1 > v1);
        let v1_1_1 = Version::parse("1.1.1")?;
        assert!(v1_1_1 > v1_1);
        Ok(())
    }

    #[test]
    fn valid_non_null_string() -> Result<()> {
        assert!(NonNulString::try_from("test_non_null.string").is_ok());
        Ok(())
    }

    #[test]
    fn invalid_non_null_string() -> Result<()> {
        assert!(NonNulString::try_from("test_null\0.string").is_err());
        Ok(())
    }

    #[test]
    fn schema() {
        schemars::schema_for!(Manifest);
    }
}
