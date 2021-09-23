use nix::{sys::stat, unistd};
use std::{
    os::unix::prelude::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::fs;

/// Return true if path is read and writeable
pub(crate) async fn is_rw(path: &Path) -> bool {
    match fs::metadata(path).await {
        Ok(stat) => {
            let same_uid = stat.uid() == unistd::getuid().as_raw();
            let same_gid = stat.gid() == unistd::getgid().as_raw();
            let mode = stat::Mode::from_bits_truncate(stat.permissions().mode());

            let is_readable = (same_uid && mode.contains(stat::Mode::S_IRUSR))
                || (same_gid && mode.contains(stat::Mode::S_IRGRP))
                || mode.contains(stat::Mode::S_IROTH);
            let is_writable = (same_uid && mode.contains(stat::Mode::S_IWUSR))
                || (same_gid && mode.contains(stat::Mode::S_IWGRP))
                || mode.contains(stat::Mode::S_IWOTH);

            is_readable && is_writable
        }
        Err(_) => false,
    }
}

pub(crate) trait PathExt {
    fn join_strip<T: AsRef<Path>>(&self, w: T) -> PathBuf;
}

impl PathExt for Path {
    fn join_strip<T: AsRef<Path>>(&self, w: T) -> PathBuf {
        self.join(match w.as_ref().strip_prefix("/") {
            Ok(stripped) => stripped,
            Err(_) => w.as_ref(),
        })
    }
}
