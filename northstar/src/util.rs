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

use nix::{sys::stat, unistd};
use std::{
    os::unix::prelude::{MetadataExt, PermissionsExt},
    path::Path,
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
