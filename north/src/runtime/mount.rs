// Copyright (c) 2019 - 2020 ESRLabs
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

use super::{
    device_mapper as dm, device_mapper,
    loopdev::{losetup, LoopControl},
};
use device_mapper::Dm;
use floating_duration::TimeAsFloat;
use log::{debug, info};
pub use nix::mount::MsFlags as MountFlags;
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
use npk::{
    archive::{ArchiveReader, Container},
    check_verity_config, parse_verity_header, VerityHeader,
};
use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    process,
};
use thiserror::Error;
use tokio::{
    fs,
    fs::metadata,
    io::{AsyncReadExt, AsyncSeekExt},
    select,
    stream::StreamExt,
    task, time,
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Device mapper error: {0:?}")]
    DeviceMapper(device_mapper::Error),
    #[error("Loop device error: {0:?}")]
    LoopDevice(super::loopdev::Error),
    #[error("IO error: {0}: {1:?}")]
    Io(String, io::Error),
    #[error("NPK error: {0:?}")]
    Npk(npk::Error),
    #[error("NPK error: {0:?}")]
    NpkArchive(npk::archive::Error),
    #[error("Inotify timeout error {0}")]
    Timeout(String),
    #[error("Task join error")]
    JoinError,
    #[error("Os error: {0:?}")]
    Os(nix::Error),
}

pub(super) async fn mount_npk_dir(
    run_dir: &Path,
    signing_keys: &HashMap<String, ed25519_dalek::PublicKey>,
    device_mapper_dev: &str,
    device_mapper: &Path,
    loop_control: &Path,
    loop_dev: &str,
    dir: &Path,
) -> Result<Vec<Container>, Error> {
    info!("Mounting containers from {}", dir.display());

    let npks = fs::read_dir(&dir)
        .await
        .map_err(|e| Error::Io(format!("Failed to read {}", dir.display()), e))?
        .filter_map(move |d| d.ok())
        .map(|d| d.path());

    let dm = Dm::new(&device_mapper).map_err(Error::DeviceMapper)?;
    let lc = LoopControl::open(loop_control, loop_dev)
        .await
        .map_err(Error::LoopDevice)?;

    let mut npks = Box::pin(npks);

    let mut containers: Vec<Vec<Container>> = vec![];
    while let Some(npk) = npks.next().await {
        containers.push(
            mount_internal(&run_dir, &signing_keys, &device_mapper_dev, &dm, &lc, &npk).await?,
        );
    }
    Ok(containers.into_iter().flatten().collect())
}

pub(super) async fn mount_npk(
    run_dir: &Path,
    signing_keys: &HashMap<String, ed25519_dalek::PublicKey>,
    device_mapper_dev: &str,
    device_mapper: &Path,
    loop_control: &Path,
    loop_dev: &str,
    npk: &Path,
) -> Result<Vec<Container>, Error> {
    debug!("Mounting {}", npk.display());

    let dm = dm::Dm::new(&device_mapper).map_err(Error::DeviceMapper)?;
    let lc = LoopControl::open(loop_control, loop_dev)
        .await
        .map_err(Error::LoopDevice)?;

    let mounted_containers =
        mount_internal(run_dir, signing_keys, device_mapper_dev, &dm, &lc, npk).await?;

    Ok(mounted_containers)
}

pub async fn umount_npk(container: &Container) -> Result<(), Error> {
    debug!("Umounting {}", container.root.display());
    unmount(&container.root).await?;

    debug!("Waiting for dm device removal");
    wait_for_file_deleted(&container.dm_dev, std::time::Duration::from_secs(5)).await?;

    debug!("Removing mountpoint {}", container.root.display());
    // Root which is the container version
    fs::remove_dir(&container.root)
        .await
        .map_err(|e| Error::Io(format!("Failed to remove {}", container.root.display()), e))?;
    // Container name
    fs::remove_dir(
        container
            .root
            .parent()
            .expect("Could not get parent dir of container!"),
    )
    .await
    .map_err(|e| Error::Io(format!("Failed to remove {}", container.root.display()), e))?;

    Ok(())
}

async fn mount_internal(
    run_dir: &Path,
    signing_keys: &HashMap<String, ed25519_dalek::PublicKey>,
    device_mapper_dev: &str,
    dm: &Dm,
    lc: &LoopControl,
    npk: &Path,
) -> Result<Vec<Container>, Error> {
    let start = time::Instant::now();

    if let Ok(meta) = metadata(&npk).await {
        debug!("Mounting NPK with size {}", meta.len());
    }
    let mut archive_reader = ArchiveReader::new(&npk, signing_keys).map_err(Error::NpkArchive)?;

    let hashes = archive_reader.extract_hashes().map_err(Error::NpkArchive)?;

    let manifest = archive_reader
        .extract_manifest_from_archive()
        .map_err(Error::NpkArchive)?;
    debug!("Loaded manifest of {}:{}", manifest.name, manifest.version);

    let (fs_offset, fs_size) = archive_reader
        .extract_fs_start_and_size()
        .map_err(Error::NpkArchive)?;

    let mut fs = fs::File::open(&npk)
        .await
        .map_err(|error| Error::Io(format!("Failed to open {:?}", npk), error))?;

    let mut header = [0u8; 512];
    fs.seek(std::io::SeekFrom::Start(
        fs_offset + hashes.fs_verity_offset,
    ))
    .await
    .map_err(|e| Error::Io("Failed to seek to verity header".into(), e))?;
    fs.read_exact(&mut header)
        .await
        .map_err(|e| Error::Io("Failed to read verity header".into(), e))?;

    let verity = parse_verity_header(&header).await.map_err(Error::Npk)?;

    check_verity_config(&verity).map_err(Error::Npk)?;

    let instances = manifest.instances.unwrap_or(1);

    let mut mounted_containers = vec![];
    for instance in 0..instances {
        let mut manifest = manifest.clone();
        if instances > 1 {
            manifest.name.push_str(&format!("-{:03}", instance));
        }
        let root = run_dir
            .join(&manifest.name)
            .join(&format!("{}", manifest.version));

        if !root.exists() {
            info!("Creating mountpoint {}", root.display());
            fs::create_dir_all(&root)
                .await
                .map_err(|e| Error::Io(format!("Failed to create mountpoint: {}", e), e))?;
        }

        let name = format!(
            "north_{}_{}_{}",
            process::id(),
            manifest.name,
            manifest.version
        );

        let dm_dev = setup_and_mount(
            dm,
            lc,
            &verity,
            &name,
            device_mapper_dev,
            hashes.fs_verity_offset,
            &hashes.fs_verity_hash,
            &npk,
            &mut fs,
            fs_offset,
            fs_size,
            &root,
        )
        .await?;

        let container = Container {
            root,
            manifest,
            dm_dev,
        };

        let duration = start.elapsed();

        info!(
            "Installed {}:{} Mounting: {:.03}s",
            container.manifest.name,
            container.manifest.version,
            duration.as_fractional_secs(),
        );
        mounted_containers.push(container);
    }

    Ok(mounted_containers)
}

pub async fn veritysetup(
    dm: &dm::Dm,
    dm_dev: &str,
    dev: &str,
    verity: &VerityHeader,
    name: &str,
    verity_hash: &str,
    size: u64,
) -> Result<PathBuf, Error> {
    debug!("Creating a read-only verity device (name: {})", &name);
    let start = time::Instant::now();
    let dm_device = dm
        .device_create(
            &name,
            &dm::DmOptions::new().set_flags(dm::DmFlags::DM_READONLY),
        )
        .await
        .map_err(Error::DeviceMapper)?;

    let verity_table = format!(
        "{} {} {} {} {} {} {} {} {} {}",
        verity.version,
        dev,
        dev,
        verity.data_block_size,
        verity.hash_block_size,
        verity.data_blocks,
        verity.data_blocks + 1,
        verity.algorithm,
        verity_hash,
        verity.salt
    );
    let table = vec![(0, size / 512, "verity".to_string(), verity_table.clone())];

    let dm_dev = PathBuf::from(format!("{}{}", dm_dev, dm_device.id() & 0xFF));

    debug!("Verity-device used: {}", dm_dev.to_string_lossy());
    dm.table_load_flags(
        name,
        &table,
        dm::DmOptions::new().set_flags(dm::DmFlags::DM_READONLY),
    )
    .await
    .map_err(Error::DeviceMapper)?;

    debug!("Resuming device");
    dm.device_suspend(&name, &dm::DmOptions::new())
        .await
        .map_err(Error::DeviceMapper)?;

    debug!("Waiting for device {}", dm_dev.display());
    while !dm_dev.exists() {
        time::sleep(time::Duration::from_millis(1)).await;
    }

    let veritysetup_duration = start.elapsed();
    debug!(
        "Verity setup took {:.03}s",
        veritysetup_duration.as_fractional_secs()
    );

    Ok(dm_dev)
}

#[allow(clippy::too_many_arguments)]
async fn setup_and_mount(
    dm: &dm::Dm,
    lc: &LoopControl,
    verity: &VerityHeader,
    name: &str,
    dm_dev: &str,
    dm_device_size: u64,
    verity_hash: &str,
    fs_path: &Path,
    fs: &mut fs::File,
    fs_offset: u64,
    lo_size: u64,
    root: &Path,
) -> Result<PathBuf, Error> {
    let mut fstype = [0u8; 4];
    fs.seek(io::SeekFrom::Start(fs_offset))
        .await
        .map_err(|e| Error::Io("Failed seek to fs type".into(), e))?;
    fs.read_exact(&mut fstype)
        .await
        .map_err(|e| Error::Io("Failed read fs type".into(), e))?;
    let fs_type = if &fstype == b"hsqs" {
        debug!("Detected SquashFS file system");
        "squashfs"
    } else {
        debug!("Defaulting to ext filesystem type");
        "ext4"
    };

    let loop_device = losetup(lc, fs_path, fs, fs_offset, lo_size)
        .await
        .map_err(Error::LoopDevice)?;

    let loop_device_id = loop_device
        .dev_id()
        .await
        .map(|(major, minor)| format!("{}:{}", major, minor))
        .map_err(Error::LoopDevice)?;

    let dm_dev = veritysetup(
        &dm,
        &dm_dev,
        &loop_device_id,
        &verity,
        name,
        verity_hash,
        dm_device_size,
    )
    .await?;

    mount(&dm_dev, root, fs_type, MountFlags::MS_RDONLY, None).await?;

    dm.device_remove(
        &name.to_string(),
        &device_mapper::DmOptions::new().set_flags(device_mapper::DmFlags::DM_DEFERRED_REMOVE),
    )
    .await
    .map_err(Error::DeviceMapper)?;

    Ok(dm_dev)
}

async fn unmount(target: &Path) -> Result<(), Error> {
    debug!("Umounting {}", target.display(),);
    task::block_in_place(|| nix::mount::umount(target.as_os_str()).map_err(Error::Os))
}

async fn mount(
    dev: &Path,
    target: &Path,
    r#type: &str,
    flags: MountFlags,
    data: Option<&str>,
) -> Result<(), Error> {
    let start = time::Instant::now();
    debug!(
        "Mount {} fs on {} to {}",
        r#type,
        dev.display(),
        target.display(),
    );
    task::block_in_place(|| {
        nix::mount::mount(
            Some(dev.as_os_str()),
            target.as_os_str(),
            Some(r#type),
            flags,
            data,
        )
        .map_err(Error::Os)
    })?;

    let mount_duration = start.elapsed();
    debug!("Mounting took {:.03}s", mount_duration.as_fractional_secs());

    Ok(())
}

async fn wait_for_file_deleted(path: &Path, timeout: time::Duration) -> Result<(), Error> {
    let notify_path = path.to_owned();
    let wait = task::spawn_blocking(move || {
        let inotify = Inotify::init(InitFlags::IN_CLOEXEC).map_err(Error::Os)?;
        inotify
            .add_watch(&notify_path, AddWatchFlags::IN_DELETE_SELF)
            .map_err(Error::Os)?;

        loop {
            if !notify_path.exists() {
                break;
            }
            inotify.read_events().map_err(Error::Os)?;
        }
        Result::<(), Error>::Ok(())
    });

    let timeout = time::sleep(timeout);
    select! {
        _ = timeout => Err(Error::Timeout(format!("Inotify error on {}", &path.display()))),
        w = wait => match w {
            Ok(r) => r,
            Err(_) => Err(Error::JoinError),
        }
    }
}
