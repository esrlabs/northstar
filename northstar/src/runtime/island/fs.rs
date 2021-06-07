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

use super::Container;
use crate::runtime::{config::Config, island::utils::PathExt};
use log::debug;
use nix::{mount::MsFlags, unistd};
use npk::manifest::{MountOption, MountOptions};
use std::path::PathBuf;
use tokio::task;

#[derive(Debug)]
pub(super) struct Mount {
    pub source: Option<PathBuf>,
    pub target: PathBuf,
    pub fstype: Option<&'static str>,
    pub flags: MsFlags,
    pub data: Option<String>,
}

impl Mount {
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

/// Prepare a list of mounts that can be done in init without any allocation.
pub(super) async fn mounts(
    config: &Config,
    container: &Container,
) -> Result<Vec<Mount>, super::Error> {
    let mut mounts = Vec::new();
    let root = container
        .root
        .canonicalize()
        .map_err(|e| super::Error::io("Canonicalize root", e))?;
    let uid = container.manifest.uid;
    let gid = container.manifest.gid;

    // /proc
    debug!("Mounting /proc");
    let target = root.join("proc");
    let flags = MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV;
    mounts.push(Mount {
        source: Some(PathBuf::from("proc")),
        target: target.clone(),
        fstype: Some("proc"),
        flags,
        data: None,
    });

    // TODO: /dev
    mounts.push(Mount {
        source: Some(PathBuf::from("/dev")),
        target: root.join("dev"),
        fstype: None,
        flags: MsFlags::MS_BIND | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        data: None,
    });

    for (target, mount) in &container.manifest.mounts {
        match &mount {
            npk::manifest::Mount::Bind { host, options } => {
                if !&host.exists() {
                    debug!(
                        "Skipping bind mount of nonexitent source {} to {}",
                        host.display(),
                        target.display()
                    );
                    continue;
                }
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
                    source: Some(host.clone()),
                    target: target.clone(),
                    fstype: None,
                    flags: MsFlags::MS_BIND | flags,
                    data: None,
                });

                if !options.contains(&MountOption::Rw) {
                    mounts.push(Mount {
                        source: Some(host.clone()),
                        target,
                        fstype: None,
                        flags: MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | flags,
                        data: None,
                    });
                }
            }
            npk::manifest::Mount::Persist => {
                let dir = config.data_dir.join(&container.manifest.name);
                if !dir.exists() {
                    debug!("Creating {}", dir.display());
                    tokio::fs::create_dir_all(&dir).await.map_err(|e| {
                        super::Error::Io(format!("Failed to create {}", dir.display()), e)
                    })?;
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
                    super::Error::os(
                        format!("Failed to chown {} to {}:{}", dir.display(), uid, gid),
                        e,
                    )
                })?;

                debug!("Mounting {} on {}", dir.display(), target.display(),);

                mounts.push(Mount {
                    source: Some(dir),
                    target: root.join_strip(target),
                    fstype: None,
                    flags: MsFlags::MS_BIND
                        | MsFlags::MS_NODEV
                        | MsFlags::MS_NOSUID
                        | MsFlags::MS_NOEXEC,
                    data: None,
                });
            }
            npk::manifest::Mount::Resource {
                name,
                version,
                dir,
                options,
            } => {
                let src = {
                    // Join the source of the resource container with the mount dir
                    let resource_root = config.run_dir.join(format!("{}:{}", name, version));
                    let dir = dir
                        .strip_prefix("/")
                        .map(|d| resource_root.join(d))
                        .unwrap_or(resource_root);

                    if !dir.exists() {
                        return Err(super::Error::StartContainerMissingResource(
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
                    options
                );

                let mut flags = options_to_flags(&options);
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
            }
            npk::manifest::Mount::Tmpfs { size } => {
                debug!(
                    "Mounting tmpfs with size {} on {}",
                    bytesize::ByteSize::b(*size),
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
            npk::manifest::Mount::Dev { .. } => { /* See above */ }
        }
    }

    Ok(mounts)
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
