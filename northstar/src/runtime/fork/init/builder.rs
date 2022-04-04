use super::{Init, Mount};
use crate::{
    common::container::Container,
    npk::{
        manifest,
        manifest::{Manifest, MountOption, MountOptions, Resource, Tmpfs},
    },
    runtime::{
        config::Config,
        error::{Context, Error},
    },
    seccomp,
};
use nix::{mount::MsFlags, unistd};
use std::{
    ffi::{c_void, CString},
    path::{Path, PathBuf},
    ptr::null,
};
use tokio::fs;

trait PathExt {
    fn join_strip<T: AsRef<Path>>(&self, w: T) -> PathBuf;
}

pub async fn build(config: &Config, manifest: &Manifest) -> Result<Init, Error> {
    let container = manifest.container();
    let root = config.run_dir.join(container.to_string());

    let capabilities = manifest.capabilities.clone();
    let console = !manifest.console.is_empty();
    let gid = manifest.gid;
    let groups = groups(manifest);
    let mounts = prepare_mounts(config, &root, manifest).await?;
    let rlimits = manifest.rlimits.clone();
    let seccomp = seccomp_filter(manifest);
    let uid = manifest.uid;

    Ok(Init {
        container,
        root,
        uid,
        gid,
        mounts,
        groups,
        capabilities,
        rlimits,
        seccomp,
        console,
    })
}

/// Generate a list of supplementary gids if the groups info can be retrieved. This
/// must happen before the init `clone` because the group information cannot be gathered
/// without `/etc` etc...
fn groups(manifest: &Manifest) -> Vec<u32> {
    if let Some(groups) = manifest.suppl_groups.as_ref() {
        let mut result = Vec::with_capacity(groups.len());
        for group in groups {
            let cgroup = CString::new(group.as_str()).unwrap(); // Check during manifest parsing
            let group_info =
                unsafe { nix::libc::getgrnam(cgroup.as_ptr() as *const nix::libc::c_char) };
            if group_info == (null::<c_void>() as *mut nix::libc::group) {
                log::warn!("Skipping invalid supplementary group {}", group);
            } else {
                let gid = unsafe { (*group_info).gr_gid };
                // TODO: Are there gids cannot use?
                result.push(gid)
            }
        }
        result
    } else {
        Vec::with_capacity(0)
    }
}

/// Generate seccomp filter applied in init
fn seccomp_filter(manifest: &Manifest) -> Option<seccomp::AllowList> {
    if let Some(seccomp) = manifest.seccomp.as_ref() {
        return Some(seccomp::seccomp_filter(
            seccomp.profile.as_ref(),
            seccomp.allow.as_ref(),
            manifest.capabilities.as_ref(),
        ));
    }
    None
}

/// Iterate the mounts of a container and assemble a list of `mount` calls to be
/// performed by init. Prepare an options persist dir. This fn fails if a resource
/// is referenced that does not exist.
async fn prepare_mounts(
    config: &Config,
    root: &Path,
    manifest: &Manifest,
) -> Result<Vec<Mount>, Error> {
    let mut mounts = vec![];
    let manifest_mounts = &manifest.mounts;

    for (target, mount) in manifest_mounts {
        match mount {
            manifest::Mount::Bind(manifest::Bind { host, options }) => {
                mounts.extend(bind(root, target, host, options));
            }
            manifest::Mount::Persist => {
                // Note that the version is intentionally not part of the path. This allows
                // upgrades with persistent data migration
                let source = config.data_dir.join(manifest.name.to_string());
                mounts.push(persist(root, &source, target, manifest.uid, manifest.gid).await?);
            }
            manifest::Mount::Proc => mounts.push(proc(root, target)),
            manifest::Mount::Resource(res) => {
                let container = Container::new(manifest.name.clone(), manifest.version.clone());
                let (mount, remount_ro) = resource(root, target, config, container, res)?;
                mounts.push(mount);
                mounts.push(remount_ro);
            }
            manifest::Mount::Tmpfs(Tmpfs { size }) => mounts.push(tmpfs(root, target, *size)),
            manifest::Mount::Dev => {}
        }
    }

    Ok(mounts)
}

fn proc(root: &Path, target: &Path) -> Mount {
    log::debug!(
        "Adding proc on {} with options ro, nosuid, noexec and nodev",
        target.display()
    );
    let source = PathBuf::from("proc");
    let target = root.join_strip(target);
    const FSTYPE: Option<&'static str> = Some("proc");
    let flags = MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV;
    Mount::new(Some(source), target, FSTYPE, flags, None)
}

fn bind(root: &Path, target: &Path, host: &Path, options: &MountOptions) -> Vec<Mount> {
    if host.exists() {
        let rw = options.contains(&MountOption::Rw);
        let mut mounts = Vec::with_capacity(if rw { 2 } else { 1 });
        if options.is_empty() {
            log::debug!(
                "Adding {} on {} with flags {}",
                host.display(),
                target.display(),
                options
            );
        } else {
            log::debug!(
                "Adding {} on {} with flags {}",
                host.display(),
                target.display(),
                options
            );
        }
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
            log::debug!(
                "Adding read only remount of {} on {}",
                host.display(),
                target.display()
            );
            flags.set(MsFlags::MS_REMOUNT, true);
            flags.set(MsFlags::MS_RDONLY, true);
            mounts.push(Mount::new(Some(source), target, None, flags, None));
        }
        mounts
    } else {
        log::debug!(
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
        log::debug!("Creating {}", source.display());
        fs::create_dir_all(&source)
            .await
            .context(format!("Failed to create {}", source.display()))?;
    }

    log::debug!("Chowning {} to {}:{}", source.display(), uid, gid);
    unistd::chown(
        source.as_os_str(),
        Some(unistd::Uid::from_raw(uid.into())),
        Some(unistd::Gid::from_raw(gid.into())),
    )
    .context(format!(
        "Failed to chown {} to {}:{}",
        source.display(),
        uid,
        gid
    ))?;

    log::debug!(
        "Adding {} on {} with options nodev, nosuid and noexec",
        source.display(),
        target.display(),
    );

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

    log::debug!(
        "Mounting {} on {} with {}",
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
    log::debug!(
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
    for opt in opt.iter() {
        match opt {
            MountOption::Rw => {}
            MountOption::NoExec => flags |= MsFlags::MS_NOEXEC,
            MountOption::NoSuid => flags |= MsFlags::MS_NOSUID,
            MountOption::NoDev => flags |= MsFlags::MS_NODEV,
            MountOption::Rec => flags |= MsFlags::MS_REC,
        }
    }
    flags
}

impl PathExt for Path {
    fn join_strip<T: AsRef<Path>>(&self, w: T) -> PathBuf {
        self.join(match w.as_ref().strip_prefix("/") {
            Ok(stripped) => stripped,
            Err(_) => w.as_ref(),
        })
    }
}
