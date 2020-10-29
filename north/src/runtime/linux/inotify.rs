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

use crate::runtime::error::InstallFailure;
use async_std::{future, task};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
use std::{fs::metadata, path::Path, time::Duration};

pub async fn wait_for_file_deleted(path: &Path, timeout: Duration) -> Result<(), InstallFailure> {
    let my_path = path.to_owned();

    future::timeout(
        timeout,
        task::spawn_blocking(move || {
            let inotify =
                Inotify::init(InitFlags::IN_CLOEXEC).map_err(|e| InstallFailure::INotifyError {
                    context: "Init inotify failed".to_string(),
                    error: e,
                })?;
            inotify
                .add_watch(&my_path, AddWatchFlags::IN_DELETE_SELF)
                .map_err(|e| InstallFailure::INotifyError {
                    context: "Add inotify watch failed".to_string(),
                    error: e,
                })?;

            loop {
                // check if the file still exists
                if metadata(&my_path).is_err() {
                    return Ok(());
                }

                inotify
                    .read_events()
                    .map_err(|e| InstallFailure::INotifyError {
                        context: "Read inotify events failed".to_string(),
                        error: e,
                    })?;
            }
        }),
    )
    .await
    .map_err(|_| {
        InstallFailure::TimeoutError(format!("Deletion of {} timed out", path.display()))
    })?
}
