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

use super::super::linux::{self, device_mapper as dm};
use floating_duration::TimeAsFloat;
use log::*;
use npk::VerityHeader;
use std::path::PathBuf;
use tokio::time;

pub async fn veritysetup(
    dm: &dm::Dm,
    dm_dev: &str,
    dev: &str,
    verity: &VerityHeader,
    name: &str,
    verity_hash: &str,
    size: u64,
) -> Result<PathBuf, linux::Error> {
    debug!("Creating a read-only verity device (name: {})", &name);
    let start = time::Instant::now();
    let dm_device = dm
        .device_create(
            &name,
            &dm::DmOptions::new().set_flags(dm::DmFlags::DM_READONLY),
        )
        .await
        .map_err(linux::Error::DeviceMapper)?;

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
    .map_err(linux::Error::DeviceMapper)?;

    debug!("Resuming device");
    dm.device_suspend(&name, &dm::DmOptions::new())
        .await
        .map_err(linux::Error::DeviceMapper)?;

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
