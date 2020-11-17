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

use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
use std::path::Path;
use thiserror::Error;
use tokio::{select, task, time};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Nix error")]
    Nix(#[from] nix::Error),
    #[error("Inotify timeout error {0}")]
    Timeout(String),
}

pub async fn wait_for_file_deleted(path: &Path, timeout: time::Duration) -> Result<(), Error> {
    let notify_path = path.to_owned();
    let wait = task::spawn_blocking(move || {
        let inotify = Inotify::init(InitFlags::IN_CLOEXEC).map_err(Error::Nix)?;
        inotify
            .add_watch(&notify_path, AddWatchFlags::IN_DELETE_SELF)
            .map_err(Error::Nix)?;

        loop {
            if !notify_path.exists() {
                break;
            }
            inotify.read_events().map_err(Error::Nix)?;
        }
        Result::<(), Error>::Ok(())
    });

    let timeout = time::sleep(timeout);
    select! {
        _ = timeout => Err(Error::Timeout(format!("Inotify error on {}", &path.display()))),
        w = wait => match w {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::Timeout(format!("Inotify error on {}", &path.display()))),
        }
    }
}
