use nix::{sys::stat, unistd};
use std::{
    borrow::Borrow,
    os::unix::prelude::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::{fs, time};

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

pub trait TimeAsFloat {
    /// Returns the duration in seconds.
    fn as_fractional_secs(&self) -> f64;
    /// Returns the duration in milliseconds.
    fn as_fractional_millis(&self) -> f64;
    /// Returns the duration in microseconds.
    fn as_fractional_micros(&self) -> f64;
}

impl<T: Borrow<time::Duration>> TimeAsFloat for T {
    fn as_fractional_secs(&self) -> f64 {
        let dur: &time::Duration = self.borrow();

        dur.as_secs() as f64 + dur.subsec_nanos() as f64 / 1_000_000_000.0
    }

    fn as_fractional_millis(&self) -> f64 {
        let dur: &time::Duration = self.borrow();

        dur.as_secs() as f64 * 1_000.0 + dur.subsec_nanos() as f64 / 1_000_000.0
    }

    fn as_fractional_micros(&self) -> f64 {
        let dur: &time::Duration = self.borrow();

        dur.as_secs() as f64 * 1_000_000.0 + dur.subsec_nanos() as f64 / 1_000.0
    }
}
