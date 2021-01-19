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

use nix::libc::{c_ulong, ioctl as nix_ioctl};
use std::{borrow::Cow, cmp, fmt, mem::size_of, path::Path, slice};
use thiserror::Error;
use tokio::{io, task};

const MIN_BUF_SIZE: usize = 16 * 1024;

/// Name max length
pub const DM_NAME_LEN: usize = 128;

pub const DM_VERSION_CMD: ::libc::c_uint = 0;
pub const DM_REMOVE_ALL_CMD: ::libc::c_uint = 1;
pub const DM_LIST_DEVICES_CMD: ::libc::c_uint = 2;
pub const DM_DEV_CREATE_CMD: ::libc::c_uint = 3;
pub const DM_DEV_REMOVE_CMD: ::libc::c_uint = 4;
pub const DM_DEV_RENAME_CMD: ::libc::c_uint = 5;
pub const DM_DEV_SUSPEND_CMD: ::libc::c_uint = 6;
pub const DM_DEV_STATUS_CMD: ::libc::c_uint = 7;
pub const DM_DEV_WAIT_CMD: ::libc::c_uint = 8;
pub const DM_TABLE_LOAD_CMD: ::libc::c_uint = 9;
pub const DM_TABLE_CLEAR_CMD: ::libc::c_uint = 10;
pub const DM_TABLE_DEPS_CMD: ::libc::c_uint = 11;
pub const DM_TABLE_STATUS_CMD: ::libc::c_uint = 12;
pub const DM_LIST_VERSIONS_CMD: ::libc::c_uint = 13;
pub const DM_TARGET_MSG_CMD: ::libc::c_uint = 14;
// We don't support this
// pub const DM_DEV_SET_GEOMETRY_CMD: ::libc::c_uint = 15;
// pub const DM_DEV_ARM_POLL_CMD: ::libc::c_uint = 16;

/// Indicator to send IOCTL to DM
const DM_IOCTL: u8 = 0xfd;
/// Major version
const DM_VERSION_MAJOR: u32 = 4;
/// Minor version
const DM_VERSION_MINOR: u32 = 0;
/// Patch level
const DM_VERSION_PATCHLEVEL: u32 = 0;

#[allow(non_camel_case_types)]
type __s8 = ::libc::c_char;
#[allow(non_camel_case_types)]
type __u8 = ::libc::c_uchar;
#[allow(non_camel_case_types)]
type __s16 = ::libc::c_short;
#[allow(non_camel_case_types)]
type __u16 = ::libc::c_ushort;
#[allow(non_camel_case_types)]
type __s32 = ::libc::c_int;
#[allow(non_camel_case_types)]
type __u32 = ::libc::c_uint;
#[allow(non_camel_case_types)]
type __s64 = ::libc::c_longlong;
#[allow(non_camel_case_types)]
type __u64 = ::libc::c_ulonglong;

#[repr(C)]
pub struct Struct_dm_ioctl {
    pub version: [__u32; 3usize],
    pub data_size: __u32,
    pub data_start: __u32,
    pub target_count: __u32,
    pub open_count: __s32,
    pub flags: __u32,
    pub event_nr: __u32,
    pub padding: __u32,
    pub dev: __u64,
    pub name: [u8; 128usize],
    pub uuid: [u8; 129usize],
    pub data: [u8; 7usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Struct_dm_target_spec {
    pub sector_start: __u64,
    pub length: __u64,
    pub status: __s32,
    pub next: __u32,
    pub target_type: [u8; 16usize],
}

impl Default for Struct_dm_target_spec {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

impl std::fmt::Debug for Struct_dm_ioctl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Struct_dm_ioctl")
            .field("version", &self.version)
            .field("data_size", &self.data_size)
            .field("data_start", &self.data_start)
            .field("target_count", &self.target_count)
            .field("open_count", &self.open_count)
            .field("flags", &self.flags)
            .field("event_nr", &self.event_nr)
            .field("dev", &self.dev)
            .field(
                "name",
                &slice_to_null(&self.name)
                    .map(|s| String::from_utf8_lossy(s))
                    .unwrap_or_else(|| Cow::Borrowed("kernel bug: unterminated dm_ioctl.name")),
            )
            .field(
                "uuid",
                &slice_to_null(&self.uuid)
                    .map(|s| String::from_utf8_lossy(s))
                    .unwrap_or_else(|| Cow::Borrowed("kernel bug: unterminated dm_ioctl.uuid")),
            )
            .finish()
    }
}

impl Default for Struct_dm_ioctl {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to opening file for device mapper: {0:?}")]
    Open(io::Error),
    #[error("Failed to ioctl: {0:?}")]
    IoCtrl(nix::Error),
    #[error("DM buffer full")]
    BufferFull,
}

#[derive(Debug)]
pub struct Dm {
    file: std::fs::File,
}

impl Dm {
    pub fn new(dm: &Path) -> Result<Dm, Error> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&dm)
            .map_err(Error::Open)?;
        Ok(Dm { file })
    }

    /// Devicemapper version information: Major, Minor, and patchlevel versions.
    pub async fn version(&self) -> Result<(u32, u32, u32), Error> {
        let mut hdr = DmOptions::new().to_ioctl_hdr(None, DmFlags::empty());

        self.do_ioctl(DM_VERSION_CMD as u8, &mut hdr, None).await?;

        Ok((hdr.version[0], hdr.version[1], hdr.version[2]))
    }

    /// Remove all DM devices and tables. Use discouraged other than
    /// for debugging.
    ///
    /// If DM_DEFERRED_REMOVE is set, the request will succeed for
    /// in-use devices, and they will be removed when released.
    ///
    /// Valid flags: DM_DEFERRED_REMOVE
    pub async fn remove_all(&self, options: &DmOptions) -> Result<(), Error> {
        let mut hdr = options.to_ioctl_hdr(None, DmFlags::DM_DEFERRED_REMOVE);

        self.do_ioctl(DM_REMOVE_ALL_CMD as u8, &mut hdr, None)
            .await?;

        Ok(())
    }

    /// Create a DM device. It starts out in a "suspended" state.
    ///
    /// Valid flags: DM_READONLY, DM_PERSISTENT_DEV
    pub async fn device_create(
        &self,
        name: &str,
        options: &DmOptions,
    ) -> Result<DeviceInfo, Error> {
        let mut hdr = options.to_ioctl_hdr(None, DmFlags::DM_READONLY | DmFlags::DM_PERSISTENT_DEV);

        Self::hdr_set_name(&mut hdr, name);

        self.do_ioctl(DM_DEV_CREATE_CMD as u8, &mut hdr, None)
            .await?;

        Ok(DeviceInfo::new(hdr))
    }

    /// Remove a DM device and its mapping tables.
    ///
    /// If DM_DEFERRED_REMOVE is set, the request for an in-use
    /// devices will succeed, and it will be removed when no longer
    /// used.
    ///
    /// Valid flags: DM_DEFERRED_REMOVE
    pub async fn device_remove(&self, id: &str, options: &DmOptions) -> Result<DeviceInfo, Error> {
        let mut hdr = options.to_ioctl_hdr(Some(id), DmFlags::DM_DEFERRED_REMOVE);

        self.do_ioctl(DM_DEV_REMOVE_CMD as u8, &mut hdr, None)
            .await?;

        Ok(DeviceInfo::new(hdr))
    }

    /// Load targets for a device into its inactive table slot.
    ///
    /// `targets` is an array of (sector_start, sector_length, type, params).
    ///
    /// `params` are target-specific, please see [Linux kernel documentation]
    /// https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/ ->
    /// Documentation/device-mapper
    /// for more.
    pub async fn table_load_flags(
        &self,
        id: &str,
        targets: &[(u64, u64, String, String)],
        options: &DmOptions,
    ) -> Result<DeviceInfo, Error> {
        let mut targs = Vec::new();

        // Construct targets first, since we need to know how many & size
        // before initializing the header.
        for t in targets {
            let mut targ = Struct_dm_target_spec {
                sector_start: t.0,
                length: t.1,
                status: 0,
                ..Default::default()
            };

            let dst: &mut [u8] = unsafe { &mut *(&mut targ.target_type[..] as *mut [u8]) };
            let bytes = t.2.as_bytes();
            assert!(
                bytes.len() <= dst.len(),
                "TargetType max length = targ.target_type.len()"
            );
            dst[..bytes.len()].clone_from_slice(bytes);

            let mut params = t.3.to_owned();
            let params_len = params.len();
            let pad_bytes = align_to(params_len + 1usize, 8usize) - params_len;
            params.extend(vec!["\0"; pad_bytes]);

            targ.next = (size_of::<Struct_dm_target_spec>() + params.len()) as u32;

            targs.push((targ, params));
        }

        let mut hdr = options.to_ioctl_hdr(Some(id), DmFlags::DM_READONLY);

        // io_ioctl() will set hdr.data_size but we must set target_count
        hdr.target_count = targs.len() as u32;

        // Flatten targets into a buf
        let mut data_in = Vec::new();

        for (targ, param) in targs {
            unsafe {
                let ptr = &targ as *const Struct_dm_target_spec as *mut u8;
                let slc = slice::from_raw_parts(ptr, size_of::<Struct_dm_target_spec>());
                data_in.extend_from_slice(slc);
            }

            data_in.extend(param.as_bytes());
        }

        self.do_ioctl(DM_TABLE_LOAD_CMD as u8, &mut hdr, Some(&data_in))
            .await?;

        Ok(DeviceInfo::new(hdr))
    }

    /// Suspend or resume a DM device, depending on if DM_SUSPEND flag
    /// is set or not.
    ///
    /// Resuming a DM device moves a table loaded into the "inactive"
    /// slot by `table_load()` into the "active" slot.
    ///
    /// Will block until pending I/O is completed unless DM_NOFLUSH
    /// flag is given. Will freeze filesystem unless DM_SKIP_LOCKFS
    /// flags is given. Additional I/O to a suspended device will be
    /// held until it is resumed.
    ///
    /// Valid flags: DM_SUSPEND, DM_NOFLUSH, DM_SKIP_LOCKFS
    pub async fn device_suspend(&self, id: &str, options: &DmOptions) -> Result<DeviceInfo, Error> {
        let mut hdr = options.to_ioctl_hdr(
            Some(id),
            DmFlags::DM_SUSPEND | DmFlags::DM_NOFLUSH | DmFlags::DM_SKIP_LOCKFS,
        );

        self.do_ioctl(DM_DEV_SUSPEND_CMD as u8, &mut hdr, None)
            .await?;

        Ok(DeviceInfo::new(hdr))
    }

    fn hdr_set_name(hdr: &mut Struct_dm_ioctl, name: &str) {
        let name_dest: &mut [u8; DM_NAME_LEN] =
            unsafe { &mut *(&mut hdr.name as *mut [u8; DM_NAME_LEN]) };
        let bytes = name.as_bytes();
        name_dest[..bytes.len()].clone_from_slice(bytes);
    }

    async fn do_ioctl(
        &self,
        ioctl: u8,
        hdr: &mut Struct_dm_ioctl,
        in_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        // Create in-buf by copying hdr and any in-data into a linear
        // Vec v.  'hdr_slc' also aliases hdr as a &[u8], used first
        // to copy the hdr into v, and later to update the
        // possibly-modified hdr.

        // Start with a large buffer to make BUFFER_FULL rare. Libdm
        // does this too.
        hdr.data_size = cmp::max(
            MIN_BUF_SIZE,
            size_of::<Struct_dm_ioctl>() + in_data.map_or(0, |x| x.len()),
        ) as u32;
        let mut v: Vec<u8> = Vec::with_capacity(hdr.data_size as usize);

        let hdr_slc = unsafe {
            let len = hdr.data_start as usize;
            let ptr = hdr as *mut Struct_dm_ioctl as *mut u8;
            slice::from_raw_parts_mut(ptr, len)
        };

        v.extend_from_slice(hdr_slc);
        if let Some(in_data) = in_data {
            v.extend(in_data.iter().cloned());
        }

        // zero out the rest
        let cap = v.capacity();
        v.resize(cap, 0);
        let mut hdr = unsafe {
            #[allow(clippy::cast_ptr_alignment)]
            (v.as_mut_ptr() as *mut Struct_dm_ioctl)
                .as_mut()
                .expect("pointer to own structure v can not be NULL")
        };
        let op =
            nix::request_code_readwrite!(DM_IOCTL, ioctl, size_of::<Struct_dm_ioctl>()) as c_ulong;

        use std::os::unix::io::AsRawFd;
        let fd = self.file.as_raw_fd();
        task::block_in_place(move || {
            loop {
                if let Err(e) = unsafe {
                    #[cfg(any(target_os = "android", target_env = "musl"))]
                    let op = op as i32;
                    nix::convert_ioctl_res!(nix_ioctl(fd, op, v.as_mut_ptr()))
                } {
                    return Err(Error::IoCtrl(e));
                }
                // If DM was able to write the requested data into the provided buffer, break the loop
                if (hdr.flags & DmFlags::DM_BUFFER_FULL.bits()) == 0 {
                    break;
                }

                // If DM_BUFFER_FULL is set, DM requires more space for the
                // response.  Double the size of the buffer and re-try the ioctl.
                // If the size of the buffer is already as large as can be possibly
                // expressed in hdr.data_size field, return an error. Never allow
                // the size to exceed u32::MAX.
                let len = v.len();
                if len == std::u32::MAX as usize {
                    return Err(Error::BufferFull);
                }
                v.resize((len as u32).saturating_mul(2) as usize, 0);

                // v.resize() may move the buffer if the requested increase doesn't fit in continuous
                // memory.  Update hdr to the possibly new address.
                hdr = unsafe {
                    #[allow(clippy::cast_ptr_alignment)]
                    (v.as_mut_ptr() as *mut Struct_dm_ioctl)
                        .as_mut()
                        .expect("pointer to own structure v can not be NULL")
                };
                hdr.data_size = v.len() as u32;
            }
            // hdr possibly modified so copy back
            hdr_slc.clone_from_slice(&v[..hdr.data_start as usize]);

            // Return header data section.
            let new_data_off = cmp::max(hdr.data_start, hdr.data_size);
            Ok(v[hdr.data_start as usize..new_data_off as usize].to_vec())
        })
    }
}

/// Encapsulates options for device mapper calls
#[derive(Debug, Default, Clone)]
pub struct DmOptions {
    flags: DmFlags,
    cookie: DmCookie,
}

impl DmOptions {
    /// Create a new empty option
    pub fn new() -> DmOptions {
        DmOptions {
            flags: DmFlags::empty(),
            cookie: DmCookie::empty(),
        }
    }

    /// Set the DmFlags value for option.  Note this call is not additive in that it sets (replaces)
    /// entire flag value in one call.  Thus if you want to incrementally add additional flags you
    /// need to retrieve current and '|' with new.
    pub fn set_flags(&mut self, flags: DmFlags) -> &mut DmOptions {
        self.flags = flags;
        self
    }

    /// Retrieve the flags value
    pub fn flags(&self) -> DmFlags {
        self.flags
    }

    /// Retrieve the cookie value (used for input in upper 16 bits of event_nr header field).
    pub fn cookie(&self) -> DmCookie {
        self.cookie
    }

    /// Generate a header to be used for IOCTL.
    pub fn to_ioctl_hdr(&self, id: Option<&str>, allowable_flags: DmFlags) -> Struct_dm_ioctl {
        let clean_flags = allowable_flags & self.flags();
        let event_nr = u32::from(self.cookie().bits()) << 16;
        let mut hdr: Struct_dm_ioctl = Default::default();

        hdr.version[0] = DM_VERSION_MAJOR;
        hdr.version[1] = DM_VERSION_MINOR;
        hdr.version[2] = DM_VERSION_PATCHLEVEL;

        hdr.flags = clean_flags.bits();
        hdr.event_nr = event_nr;

        hdr.data_start = size_of::<Struct_dm_ioctl>() as u32;

        if let Some(id) = id {
            Dm::hdr_set_name(&mut hdr, id);
        }

        hdr
    }
}

/// Contains information about the device.
#[derive(Debug)]
pub struct DeviceInfo {
    /// ioctl argument consists of a single chunk of memory, with this
    /// structure at the start.
    hdr: Struct_dm_ioctl,
}

impl DeviceInfo {
    pub fn new(hdr: Struct_dm_ioctl) -> DeviceInfo {
        DeviceInfo { hdr }
    }

    pub fn id(&self) -> u64 {
        self.hdr.dev
    }
}

/// A struct containing the device's major and minor numbers
///
/// Also allows conversion to/from a single 64bit dev_t value.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Device {
    /// Device major number
    pub major: u32,
    /// Device minor number
    pub minor: u32,
}

bitflags::bitflags! {
    /// Flags used by devicemapper.
    #[derive(Default)]
    pub struct DmFlags: __u32 {
        /// In: Device should be read-only.
        /// Out: Device is read-only.
        #[allow(clippy::identity_op)]
        const DM_READONLY             = (1 << 0);
        /// In: Device should be suspended.
        /// Out: Device is suspended.
        const DM_SUSPEND              = (1 << 1);
        /// In: Use passed-in minor number.
        const DM_PERSISTENT_DEV       = (1 << 3);
        /// In: STATUS command returns table info instead of status.
        const DM_STATUS_TABLE         = (1 << 4);
        /// Out: Active table is present.
        const DM_ACTIVE_PRESENT       = (1 << 5);
        /// Out: Inactive table is present.
        const DM_INACTIVE_PRESENT     = (1 << 6);
        /// Out: Passed-in buffer was too small.
        const DM_BUFFER_FULL          = (1 << 8);
        /// Obsolete.
        const DM_SKIP_BDGET           = (1 << 9);
        /// In: Avoid freezing filesystem when suspending.
        const DM_SKIP_LOCKFS          = (1 << 10);
        /// In: Suspend without flushing queued I/Os.
        const DM_NOFLUSH              = (1 << 11);
        /// In: Query inactive table instead of active.
        const DM_QUERY_INACTIVE_TABLE = (1 << 12);
        /// Out: A uevent was generated, the caller may need to wait for it.
        const DM_UEVENT_GENERATED     = (1 << 13);
        /// In: Rename affects UUID field, not name field.
        const DM_UUID                 = (1 << 14);
        /// In: All buffers are wiped after use. Use when handling crypto keys.
        const DM_SECURE_DATA          = (1 << 15);
        /// Out: A message generated output data.
        const DM_DATA_OUT             = (1 << 16);
        /// In: Do not remove in-use devices.
        /// Out: Device scheduled to be removed when closed.
        const DM_DEFERRED_REMOVE      = (1 << 17);
        /// Out: Device is suspended internally.
        const DM_INTERNAL_SUSPEND     = (1 << 18);
    }
}

bitflags::bitflags! {
    /// Flags used by devicemapper, see:
    /// https://sourceware.org/git/?p=lvm2.git;a=blob;f=libdm/libdevmapper.h#l3627
    /// for complete information about the meaning of the flags.
    #[derive(Default)]
    pub struct DmCookie: __u16 {
        #[allow(clippy::identity_op)]
        /// Disables basic device-mapper udev rules that create symlinks in /dev/<DM_DIR>
        /// directory.
        const DM_UDEV_DISABLE_DM_RULES_FLAG = (1 << 0);
        /// Disable subsystem udev rules, but allow general DM udev rules to run.
        const DM_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG = (1 << 1);
        /// Disable dm udev rules which create symlinks in /dev/disk/* directory.
        const DM_UDEV_DISABLE_DISK_RULES_FLAG = (1 << 2);
        /// Disable all rules that are not general dm nor subsystem related.
        const DM_UDEV_DISABLE_OTHER_RULES_FLAG = (1 << 3);
        /// Instruct udev rules to give lower priority to the device.
        const DM_UDEV_LOW_PRIORITY_FLAG = (1 << 4);
        /// Disable libdevmapper's node management.
        const DM_UDEV_DISABLE_LIBRARY_FALLBACK = (1 << 5);
        /// Automatically appended to all IOCTL calls issues by libdevmapper for generating
        /// udev uevents.
        const DM_UDEV_PRIMARY_SOURCE_FLAG = (1 << 6);
    }
}

/// Return slc up to the first \0, or None
fn slice_to_null(slc: &[u8]) -> Option<&[u8]> {
    slc.iter().position(|c| *c == b'\0').map(|i| &slc[..i])
}

/// The smallest number divisible by `align_to` and at least `num`.
/// Precondition: `align_to` is a power of 2.
/// Precondition: `num` + `align_to` < usize::MAX + 1.
pub fn align_to(num: usize, align_to: usize) -> usize {
    let agn = align_to - 1;

    (num + agn) & !agn
}
