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

use super::data_model::DataInit;
use bitflags::bitflags;

// UAPI for device mapper can be found at include/uapi/linux/dm-ioctl.h

pub const DM_IOCTL: u8 = 0xfd;

#[repr(u16)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub enum Cmd {
    DM_VERSION = 0,
    DM_REMOVE_ALL,
    DM_LIST_DEVICES,
    DM_DEV_CREATE,
    DM_DEV_REMOVE,
    DM_DEV_RENAME,
    DM_DEV_SUSPEND,
    DM_DEV_STATUS,
    DM_DEV_WAIT,
    DM_TABLE_LOAD,
    DM_TABLE_CLEAR,
    DM_TABLE_DEPS,
    DM_TABLE_STATUS,
    DM_LIST_VERSIONS,
    DM_TARGET_MSG,
    DM_DEV_SET_GEOMETRY,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DmIoctl {
    pub version: [u32; 3],
    pub data_size: u32,
    pub data_start: u32,
    pub target_count: u32,
    pub open_count: i32,
    pub flags: Flag,
    pub event_nr: u32,
    pub padding: u32,
    pub dev: u64,
    pub name: [u8; DM_NAME_LEN],
    pub uuid: [u8; DM_UUID_LEN],
    pub data: [u8; 7],
}

// SAFETY: C struct is safe to be initialized from raw data
unsafe impl DataInit for DmIoctl {}

pub const DM_VERSION_MAJOR: u32 = 4;
pub const DM_VERSION_MINOR: u32 = 0;
pub const DM_VERSION_PATCHLEVEL: u32 = 0;

pub const DM_NAME_LEN: usize = 128;
pub const DM_UUID_LEN: usize = 129;
pub const DM_MAX_TYPE_NAME: usize = 16;

bitflags! {
   #[derive(Copy, Clone)]
    pub struct Flag: u32 {
        const DM_READONLY_FLAG = 1 << 0;
        const DM_SUSPEND_FLAG = 1 << 1;
        const DM_PERSISTENT_DEV_FLAG = 1 << 3;
        const DM_STATUS_TABLE_FLAG = 1 << 4;
        const DM_ACTIVE_PRESENT_FLAG = 1 << 5;
        const DM_INACTIVE_PRESENT_FLAG = 1 << 6;
        const DM_BUFFER_FULL_FLAG = 1 << 8;
        const DM_SKIP_BDGET_FLAG = 1 << 9;
        const DM_SKIP_LOCKFS_FLAG = 1 << 10;
        const DM_NOFLUSH_FLAG = 1 << 11;
        const DM_QUERY_INACTIVE_TABLE_FLAG = 1 << 12;
        const DM_UEVENT_GENERATED_FLAG = 1 << 13;
        const DM_UUID_FLAG = 1 << 14;
        const DM_SECURE_DATA_FLAG = 1 << 15;
        const DM_DATA_OUT_FLAG = 1 << 16;
        const DM_DEFERRED_REMOVE = 1 << 17;
        const DM_INTERNAL_SUSPEND_FLAG = 1 << 18;
    }
}
