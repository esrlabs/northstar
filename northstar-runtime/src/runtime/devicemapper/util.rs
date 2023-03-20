/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use anyhow::{bail, Result};
use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};

/// Returns when the file exists on the given `path` or timeout (1s) occurs.
pub fn wait_for_path<P: AsRef<Path>>(path: P) -> Result<()> {
    const TIMEOUT: Duration = Duration::from_secs(10);
    const INTERVAL: Duration = Duration::from_millis(1);
    let begin = Instant::now();
    while !path.as_ref().exists() {
        if begin.elapsed() > TIMEOUT {
            bail!("{:?} not found. TIMEOUT.", path.as_ref());
        }
        thread::sleep(INTERVAL);
    }
    Ok(())
}
