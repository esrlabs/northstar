// Copyright (c) 2021 ESRLabs
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

use super::Error;
use crate::{
    common::container::Container,
    npk::{
        manifest,
        manifest::{Manifest, MountOption, MountOptions, Resource, Tmpfs},
    },
    runtime::config::Config,
    util::PathExt,
};
use log::debug;
use nix::{
    libc::makedev,
    mount::MsFlags,
    sys::stat::{Mode, SFlag},
    unistd,
    unistd::{chown, Gid, Uid},
};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tokio::fs::symlink;

/// The minimal version of the /dev is maintained in a tmpdir. This tmpdir
/// must be held for the lifetime of the Process
pub(crate) type Dev = Option<TempDir>;

/// Instructions for mount system call done in init
#[derive(Debug)]
pub(super) struct Mount {
    pub source: Option<PathBuf>,
    pub target: PathBuf,
    pub fstype: Option<&'static str>,
    pub flags: MsFlags,
    pub data: Option<String>,
    pub error_msg: String,
}

impl Mount {
    pub fn new(
        source: Option<PathBuf>,
        target: PathBuf,
        fstype: Option<&'static str>,
        flags: MsFlags,
        data: Option<String>,
    ) -> Mount {
        let error_msg = format!(
            "Failed to mount '{}' of type '{}' on '{}' with flags '{:?}' and data '{}'",
            source.clone().unwrap_or_default().display(),
            fstype.unwrap_or_default(),
            target.display(),
            flags,
            data.clone().unwrap_or_default()
        );
        Mount {
            source,
            target,
            fstype,
            flags,
            data,
            error_msg,
        }
    }

    /// Execute this mount call
    pub(super) fn mount(&self) {
        nix::mount::mount(
            self.source.as_ref(),
            &self.target,
            self.fstype,
            self.flags,
            self.data.as_deref(),
        )
        .expect(&self.error_msg);
    }
}

/// Iterate the mounts of a container and assemble a list of `mount` calls to be
/// performed by init. Prepare an options persist dir. This fn fails if a resource
/// is referenced that does not exist.
pub(super) async fn prepare_mounts(
    config: &Config,
    root: &Path,
    manifest: Manifest,
) -> Result<(Vec<Mount>, Dev), Error> {
    let mut mounts = Vec::new();
    let mut dev = None;

    mounts.push(proc(root));

    let manifest_mounts = &manifest.mounts;

    for (target, mount) in manifest_mounts {
        match &mount {
            manifest::Mount::Bind(manifest::Bind { host, options }) => {
                mounts.extend(bind(root, target, host, options));
            }
            manifest::Mount::Persist => {
                // Note that the version is intentionally not part of the path. This allows
                // upgrades with persistent data migration
                let source = config.data_dir.join(manifest.name.to_string());
                mounts.push(persist(root, &source, target, manifest.uid, manifest.gid).await?);
            }
            manifest::Mount::Resource(res) => {
                let container = Container::new(manifest.name.clone(), manifest.version.clone());
                let (mount, remount_ro) = resource(root, target, config, container, res)?;
                mounts.push(mount);
                mounts.push(remount_ro);
            }
            manifest::Mount::Tmpfs(Tmpfs { size }) => mounts.push(tmpfs(root, target, *size)),
            manifest::Mount::Dev => {
                let (d, mount, remount) = self::dev(root, manifest.uid, manifest.gid).await;
                mounts.push(mount);
                mounts.push(remount);
                dev = d
            }
        }
    }

    // No dev configured in mounts: Use minimal version
    if dev.is_none() && !manifest_mounts.contains_key(Path::new("/dev")) {
        let (d, mount, remount) = self::dev(root, manifest.uid, manifest.gid).await;
        mounts.push(mount);
        mounts.push(remount);
        dev = d;
    }

    Ok((mounts, dev))
}

fn proc(root: &Path) -> Mount {
    debug!("Mounting /proc");
    let source = PathBuf::from("proc");
    let target = root.join("proc");
    let fstype = "proc";
    let flags = MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV;
    Mount::new(Some(source), target, Some(fstype), flags, None)
}

fn bind(root: &Path, target: &Path, host: &Path, options: &MountOptions) -> Vec<Mount> {
    if host.exists() {
        let rw = options.contains(&MountOption::Rw);
        let mut mounts = Vec::with_capacity(if rw { 2 } else { 1 });
        debug!(
            "Mounting {} on {} with {:?}",
            host.display(),
            target.display(),
            options.iter().collect::<Vec<_>>(),
        );
        let source = host.to_owned();
        let target = root.join_strip(target);
        let mut flags = options_to_flags(options);
        flags.set(MsFlags::MS_BIND, true);
        mounts.push(Mount::new(
            Some(source.clone()),
            target.clone(),
            None,
            flags,
            None,
        ));

        if !rw {
            flags.set(MsFlags::MS_REMOUNT, true);
            flags.set(MsFlags::MS_RDONLY, true);
            mounts.push(Mount::new(Some(source), target, None, flags, None));
        }
        mounts
    } else {
        debug!(
            "Skipping bind mount of nonexistent source {} to {}",
            host.display(),
            target.display()
        );
        vec![]
    }
}

async fn persist(
    root: &Path,
    source: &Path,
    target: &Path,
    uid: u16,
    gid: u16,
) -> Result<Mount, Error> {
    if !source.exists() {
        debug!("Creating {}", source.display());
        tokio::fs::create_dir_all(&source)
            .await
            .map_err(|e| Error::Io(format!("Failed to create {}", source.display()), e))?;
    }

    debug!("Chowning {} to {}:{}", source.display(), uid, gid);
    unistd::chown(
        source.as_os_str(),
        Some(unistd::Uid::from_raw(uid.into())),
        Some(unistd::Gid::from_raw(gid.into())),
    )
    .map_err(|e| {
        Error::os(
            format!("Failed to chown {} to {}:{}", source.display(), uid, gid),
            e,
        )
    })?;

    debug!("Mounting {} on {}", source.display(), target.display(),);

    let target = root.join_strip(target);
    let flags = MsFlags::MS_BIND | MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC;
    Ok(Mount::new(
        Some(source.to_owned()),
        target,
        None,
        flags,
        None,
    ))
}

fn resource(
    root: &Path,
    target: &Path,
    config: &Config,
    container: Container,
    resource: &Resource,
) -> Result<(Mount, Mount), Error> {
    let src = {
        // Join the source of the resource container with the mount dir
        let resource_root = config
            .run_dir
            .join(format!("{}:{}", resource.name, resource.version));
        let dir = resource
            .dir
            .strip_prefix("/")
            .map(|d| resource_root.join(d))
            .unwrap_or(resource_root);

        if !dir.exists() {
            return Err(Error::StartContainerMissingResource(
                container.clone(),
                container,
            ));
        }

        dir
    };

    debug!(
        "Mounting {} on {} with {:?}",
        src.display(),
        target.display(),
        resource.options
    );

    let target = root.join_strip(target);
    let mut flags = options_to_flags(&resource.options);
    flags |= MsFlags::MS_RDONLY | MsFlags::MS_BIND;
    let mount = Mount::new(Some(src.clone()), target.clone(), None, flags, None);

    // Remount ro
    flags.set(MsFlags::MS_REMOUNT, true);
    let remount_ro = Mount::new(Some(src), target, None, flags, None);
    Ok((mount, remount_ro))
}

fn tmpfs(root: &Path, target: &Path, size: u64) -> Mount {
    debug!(
        "Mounting tmpfs with size {} on {}",
        bytesize::ByteSize::b(size),
        target.display()
    );
    let target = root.join_strip(target);
    let fstype = "tmpfs";
    let flags = MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC;
    let data = format!("size={},mode=1777", size);
    Mount::new(None, target, Some(fstype), flags, Some(data))
}

fn options_to_flags(opt: &MountOptions) -> MsFlags {
    let mut flags = MsFlags::empty();
    for opt in opt {
        match opt {
            MountOption::Rw => {}
            MountOption::NoExec => flags |= MsFlags::MS_NOEXEC,
            MountOption::NoSuid => flags |= MsFlags::MS_NOSUID,
            MountOption::NoDev => flags |= MsFlags::MS_NODEV,
        }
    }
    flags
}

async fn dev(root: &Path, uid: u16, gid: u16) -> (Dev, Mount, Mount) {
    let dir = TempDir::new().expect("Failed to create tempdir");
    debug!("Creating devfs in {}", dir.path().display());

    dev_devices(dir.path(), uid, gid);
    dev_symlinks(dir.path()).await;

    let source = dir.path().to_path_buf();
    let mut flags = MsFlags::MS_BIND | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC;
    let target = root.join("dev");
    let mount = Mount::new(Some(source.clone()), target.clone(), None, flags, None);

    flags.set(MsFlags::MS_REMOUNT, true);
    let remount = Mount::new(Some(source), target, None, flags, None);
    (Some(dir), mount, remount)
}

fn dev_devices(dir: &Path, uid: u16, gid: u16) {
    use nix::sys::stat::mknod;

    for (dev, major, minor) in &[
        ("full", 1, 7),
        ("null", 1, 3),
        ("random", 1, 8),
        ("tty", 5, 0),
        ("urandom", 1, 9),
        ("zero", 1, 5),
    ] {
        let dev_path = dir.join(dev);
        let dev = unsafe { makedev(*major, *minor) };
        mknod(dev_path.as_path(), SFlag::S_IFCHR, Mode::all(), dev).expect("Failed to mknod");
        chown(
            dev_path.as_path(),
            Some(Uid::from_raw(uid.into())),
            Some(Gid::from_raw(gid.into())),
        )
        .expect("Failed to chown");
    }
}

async fn dev_symlinks(dir: &Path) {
    let kcore = Path::new("/proc/kcore");
    if kcore.exists() {
        symlink(kcore, dir.join("kcore"))
            .await
            .expect("Failed to create symlink");
    }

    let defaults = [
        ("/proc/self/fd", "fd"),
        ("/proc/self/fd/0", "stdin"),
        ("/proc/self/fd/1", "stdout"),
        ("/proc/self/fd/2", "stderr"),
    ];
    for &(src, dst) in defaults.iter() {
        symlink(src, dir.join(dst))
            .await
            .expect("Failed to create symlink");
    }
}
