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

use floating_duration::TimeAsFloat;
use libc::ioctl;
use log::{debug, warn};
use nix::{errno::Errno, Error::Sys};
use std::{
    os::unix::prelude::*,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tokio::{fs, io, sync::Mutex, task, time};

const LOOP_SET_FD: u16 = 0x4C00;
//const LOOP_CLR_FD: u16 = 0x4C01;
const LOOP_SET_STATUS64: u16 = 0x4C04;
const LOOP_SET_DIRECT_IO: u16 = 0x4C08;
const LOOP_FLAG_READ_ONLY: u32 = 0x01;
const LOOP_FLAG_AUTOCLEAR: u32 = 0x04;
const LOOP_CTL_GET_FREE: u16 = 0x4C82;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to open loop control")]
    Open(#[from] io::Error),
    #[error("Failed to find or allocate free loop device")]
    NoFreeDeviceFound,
    #[error("Failed to add new loop device")]
    DeviceAlreadyAllocated,
    #[error("Failed to associate loop device with open file")]
    AssociateWithOpenFile,
    #[error("Set Loop status exceeded number of retries ({0})")]
    StatusWriteBusy(usize),
    #[error("Failed to set loop status")]
    SetStatusFailed(#[from] nix::Error),
    #[error("Failed to set direct I/O mode")]
    DirectIo,
    #[error("Failed to dis-associate loop device from file descriptor")]
    Detach,
}

#[derive(Debug)]
pub(super) struct LoopControl {
    control: Mutex<fs::File>,
    dev: String,
}

struct ControlLock {
    control_fd: RawFd,
}

impl ControlLock {
    pub async fn new(control_fd: RawFd) -> Result<ControlLock, Error> {
        let result = task::block_in_place(|| {
            nix::fcntl::flock(control_fd, nix::fcntl::FlockArg::LockExclusive)
        });
        match result {
            Ok(_) => debug!("Acquired control lock"),
            Err(e) => {
                warn!("Failed to lock control {:?}", e);
                panic!("Failed to lock control");
            }
        }

        Ok(ControlLock { control_fd })
    }
}

impl Drop for ControlLock {
    fn drop(&mut self) {
        match nix::fcntl::flock(self.control_fd, nix::fcntl::FlockArg::Unlock) {
            Ok(_) => debug!("Released control lock"),
            Err(e) => panic!(
                "Failed to release control lock on {}: {}",
                self.control_fd, e
            ),
        }
    }
}

impl LoopControl {
    pub async fn open(control: &Path, dev: &str) -> Result<LoopControl, Error> {
        Ok(LoopControl {
            control: fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&control)
                .await
                .map_err(Error::Open)
                .map(Mutex::new)?,
            dev: dev.into(),
        })
    }

    pub async fn losetup(
        &self,
        file_fd: RawFd,
        offset: u64,
        sizelimit: u64,
        read_only: bool,
        auto_clear: bool,
    ) -> Result<LoopDevice, Error> {
        let start = time::Instant::now();

        // Lock the fd to avoid races within *this* runtime instance
        let control_fd = self.control.lock().await;

        // Lock the loopback control file via fcntl. Sync between multiple northstar instances
        let lock = ControlLock::new(control_fd.as_raw_fd()).await?;

        let loop_device = task::block_in_place(move || {
            // Get next free loop device
            let index = unsafe { ioctl(control_fd.as_raw_fd(), LOOP_CTL_GET_FREE.into()) };
            let loop_device_path = match index {
                n if n < 0 => return Err(Error::NoFreeDeviceFound),
                n => PathBuf::from(&format!("{}{}", self.dev, n)),
            };

            debug!("Using loop dev {}", loop_device_path.display());

            // Open e.g. /dev/loop4
            let loop_device_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&loop_device_path)
                .map_err(Error::Open)?;

            // Attach the file => Associate the loop device with the open file
            if unsafe { ioctl(loop_device_file.as_raw_fd(), LOOP_SET_FD.into(), file_fd) } < 0 {
                return Err(Error::AssociateWithOpenFile);
            }

            // Set offset and limit for backing_file
            log::debug!("Setting offset {} and limit {}", offset, sizelimit);
            let mut info = loop_info64 {
                lo_offset: offset,
                lo_sizelimit: sizelimit,
                ..Default::default()
            };
            if read_only {
                info.lo_flags |= LOOP_FLAG_READ_ONLY;
            }
            if auto_clear {
                info.lo_flags |= LOOP_FLAG_AUTOCLEAR;
            }

            const MAX_RETRIES: usize = 10;

            for _ in 0..MAX_RETRIES {
                let code = unsafe {
                    ioctl(
                        loop_device_file.as_raw_fd(),
                        LOOP_SET_STATUS64.into(),
                        &mut info,
                    )
                };

                match Errno::result(code) {
                    Ok(_) => break,
                    nix::Result::Err(Sys(Errno::EAGAIN)) => {
                        warn!("Received a EAGAIN during lo attach");
                        // this error means the call should be retried
                        std::thread::sleep(time::Duration::from_millis(50));
                    }
                    nix::Result::Err(e) => {
                        return Err(Error::SetStatusFailed(e));
                    }
                }
            }

            // Unlock the loopback control lock
            drop(lock);
            drop(control_fd);

            // Try to set direct IO
            if unsafe { ioctl(loop_device_file.as_raw_fd(), LOOP_SET_DIRECT_IO.into(), 1) } < 0 {
                warn!(
                    "Failed to enable direct IO on {}",
                    loop_device_path.display()
                );
            }

            // Get major/minor
            let attr = loop_device_file.metadata()?;
            let rdev = attr.rdev();
            let major = ((rdev >> 32) & 0xFFFF_F000) | ((rdev >> 8) & 0xFFF);
            let minor = ((rdev >> 12) & 0xFFFF_FF00) | (rdev & 0xFF);

            let loop_device = LoopDevice {
                device: loop_device_file,
                path: loop_device_path,
                major,
                minor,
            };

            Ok(loop_device)
        })?;

        let losetup_duration = start.elapsed();
        debug!(
            "Loopback setup took {:.03}s",
            losetup_duration.as_fractional_secs(),
        );

        Ok(loop_device)
    }
}

/// Interface to a loop device ie `/dev/loop0`.
#[derive(Debug)]
pub(super) struct LoopDevice {
    device: std::fs::File,
    path: PathBuf,
    major: u64,
    minor: u64,
}

impl AsRawFd for LoopDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.device.as_raw_fd()
    }
}

impl LoopDevice {
    /// Get the path of the loop device.
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Get major and minor number of device
    pub fn dev_id(&self) -> (u64, u64) {
        (self.major, self.minor)
    }
}

#[repr(C)]
struct loop_info64 {
    pub lo_device: u64,
    pub lo_inode: u64,
    pub lo_rdevice: u64,
    pub lo_offset: u64,
    pub lo_sizelimit: u64,
    pub lo_number: u32,
    pub lo_encrypt_type: u32,
    pub lo_encrypt_key_size: u32,
    pub lo_flags: u32,
    pub lo_file_name: [u8; 64],
    pub lo_crypt_name: [u8; 64],
    pub lo_encrypt_key: [u8; 32],
    pub lo_init: [u64; 2],
}

impl Default for loop_info64 {
    fn default() -> loop_info64 {
        loop_info64 {
            lo_device: 0,
            lo_inode: 0,
            lo_rdevice: 0,
            lo_offset: 0,
            lo_sizelimit: 0,
            lo_number: 0,
            lo_encrypt_type: 0,
            lo_encrypt_key_size: 0,
            lo_flags: 0,
            lo_file_name: [0; 64],
            lo_crypt_name: [0; 64],
            lo_encrypt_key: [0; 32],
            lo_init: [0; 2],
        }
    }
}
