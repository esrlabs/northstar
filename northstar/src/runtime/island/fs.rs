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

use super::{Container, Error};
use crate::runtime::{config::Config, island::utils::PathExt};
use log::debug;
use nix::{
    libc::makedev,
    mount::MsFlags,
    sys::stat::{Mode, SFlag},
    unistd,
    unistd::{chown, Gid, Uid},
};
use npk::manifest::{self, Manifest, MountOption, MountOptions, Resource, Tmpfs};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tokio::{fs::symlink, task};

/// The minimal version of the /dev is maintained in a tmpdir. This tmpdir
/// must be held for the lifetime of the IslandProzess
pub(crate) type Dev = Option<TempDir>;

/// Mount systemcall instruction done in init
#[derive(Debug)]
pub(super) struct Mount {
    pub source: Option<PathBuf>,
    pub target: PathBuf,
    pub fstype: Option<&'static str>,
    pub flags: MsFlags,
    pub data: Option<String>,
}

impl Mount {
    /// Execute this mount call
    pub(super) fn mount(&self) {
        if !self.target.exists() {
            panic!("Missing mount point {}", self.target.display())
        }

        nix::mount::mount(
            self.source.as_ref(),
            &self.target,
            self.fstype,
            self.flags,
            self.data.as_deref(),
        )
        .unwrap_or_else(|_| panic!("Failed to mount {:?}", self));
    }
}

/// Iterate the mounts of a container and assemble a list of `mount` calls to be
/// performed by init.
pub(super) async fn mounts(
    config: &Config,
    container: &Container,
) -> Result<(Vec<Mount>, Dev), Error> {
    let mut mounts = Vec::new();
    let mut dev = None;
    let root = container
        .root
        .canonicalize()
        .map_err(|e| Error::io("Canonicalize root", e))?;

    proc(&root, &mut mounts);

    for (target, mount) in &container.manifest.mounts {
        match &mount {
            manifest::Mount::Bind(manifest::Bind { host, options }) => {
                bind(&root, target, host, options, &mut mounts)
            }
            manifest::Mount::Persist => {
                persist(&root, target, config, container, &mut mounts).await?
            }
            manifest::Mount::Resource(res) => {
                resource(&root, target, config, container, res, &mut mounts)?;
            }
            manifest::Mount::Tmpfs(Tmpfs { size }) => tmpfs(&root, target, *size, &mut mounts),
            manifest::Mount::Dev(d) => {
                dev = self::dev(&root, d, &container.manifest, &mut mounts).await;
            }
        }
    }

    // No dev configured in mounts: Use minimal version
    if dev.is_none() {
        dev = self::dev(
            &root,
            &manifest::Dev::Minimal,
            &container.manifest,
            &mut mounts,
        )
        .await;
    }

    Ok((mounts, dev))
}

fn proc(root: &Path, mounts: &mut Vec<Mount>) {
    debug!("Mounting /proc");
    let target = root.join("proc");
    let flags = MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV;
    mounts.push(Mount {
        source: Some(PathBuf::from("proc")),
        target,
        fstype: Some("proc"),
        flags,
        data: None,
    });
}

fn bind(root: &Path, target: &Path, host: &Path, options: &MountOptions, mounts: &mut Vec<Mount>) {
    if host.exists() {
        debug!(
            "Mounting {} on {} with {:?}",
            host.display(),
            target.display(),
            options.iter().collect::<Vec<_>>(),
        );
        let target = root.join_strip(target);
        let mut flags = options_to_flags(&options);
        flags.set(MsFlags::MS_BIND, true);
        mounts.push(Mount {
            source: Some(host.to_owned()),
            target: target.clone(),
            fstype: None,
            flags: MsFlags::MS_BIND | flags,
            data: None,
        });

        if !options.contains(&MountOption::Rw) {
            mounts.push(Mount {
                source: Some(host.to_owned()),
                target,
                fstype: None,
                flags: MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | flags,
                data: None,
            });
        }
    } else {
        debug!(
            "Skipping bind mount of nonexitent source {} to {}",
            host.display(),
            target.display()
        );
    }
}

async fn persist(
    root: &Path,
    target: &Path,
    config: &Config,
    container: &Container,
    mounts: &mut Vec<Mount>,
) -> Result<(), Error> {
    let uid = container.manifest.uid;
    let gid = container.manifest.gid;
    let dir = config.data_dir.join(&container.manifest.name);

    if !dir.exists() {
        debug!("Creating {}", dir.display());
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| Error::Io(format!("Failed to create {}", dir.display()), e))?;
    }

    debug!("Chowning {} to {}:{}", dir.display(), uid, gid);
    task::block_in_place(|| {
        unistd::chown(
            dir.as_os_str(),
            Some(unistd::Uid::from_raw(uid)),
            Some(unistd::Gid::from_raw(gid)),
        )
    })
    .map_err(|e| {
        Error::os(
            format!("Failed to chown {} to {}:{}", dir.display(), uid, gid),
            e,
        )
    })?;

    debug!("Mounting {} on {}", dir.display(), target.display(),);

    mounts.push(Mount {
        source: Some(dir),
        target: root.join_strip(target),
        fstype: None,
        flags: MsFlags::MS_BIND | MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        data: None,
    });
    Ok(())
}

fn resource(
    root: &Path,
    target: &Path,
    config: &Config,
    container: &Container,
    resource: &Resource,
    mounts: &mut Vec<Mount>,
) -> Result<(), Error> {
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
                container.container.clone(),
                container.container.clone(),
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

    let mut flags = options_to_flags(&resource.options);
    flags |= MsFlags::MS_RDONLY | MsFlags::MS_BIND;

    let target = root.join_strip(target);
    mounts.push(Mount {
        source: Some(src.clone()),
        target: target.clone(),
        fstype: None,
        flags,
        data: None,
    });

    // Remount ro
    mounts.push(Mount {
        source: Some(src),
        target,
        fstype: None,
        flags: MsFlags::MS_REMOUNT | flags,
        data: None,
    });
    Ok(())
}

fn tmpfs(root: &Path, target: &Path, size: u64, mounts: &mut Vec<Mount>) {
    debug!(
        "Mounting tmpfs with size {} on {}",
        bytesize::ByteSize::b(size),
        target.display()
    );
    mounts.push(Mount {
        source: None,
        target: root.join_strip(target),
        fstype: Some("tmpfs"),
        flags: MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        data: Some(format!("size={},mode=1777", size)),
    });
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

async fn dev(
    root: &Path,
    config: &npk::manifest::Dev,
    manifest: &Manifest,
    mounts: &mut Vec<Mount>,
) -> Dev {
    match config {
        npk::manifest::Dev::Full => {
            debug!("Bind mounting /dev");
            mounts.push(Mount {
                source: Some(PathBuf::from("/dev")),
                target: root.join("dev"),
                fstype: None,
                flags: MsFlags::MS_BIND | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
                data: None,
            });
            None
        }
        npk::manifest::Dev::Minimal => {
            let dir = task::block_in_place(|| TempDir::new().expect("Failed to create tempdir"));
            debug!("Creating devfs in {}", dir.path().display());
            task::block_in_place(|| dev_devices(dir.path(), manifest.uid, manifest.gid));
            dev_symlinks(dir.path()).await;

            let flags = MsFlags::MS_BIND | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC;

            mounts.push(Mount {
                source: Some(dir.path().into()),
                target: root.join("dev"),
                fstype: None,
                flags,
                data: None,
            });

            mounts.push(Mount {
                source: Some(dir.path().into()),
                target: root.join("dev"),
                fstype: None,
                flags: MsFlags::MS_REMOUNT | flags,
                data: None,
            });

            Some(dir)
        }
    }
}

fn dev_devices(dir: &Path, uid: u32, gid: u32) {
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
            Some(Uid::from_raw(uid)),
            Some(Gid::from_raw(gid)),
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
