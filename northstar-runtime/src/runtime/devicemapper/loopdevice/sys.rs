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

use super::super::data_model::DataInit;
use bitflags::bitflags;

// This UAPI is copied and converted from include/uapi/linux/loop.h Note that this module doesn't
// implement all the features introduced in loop(4). Only the features that are required to support
// the `apkdmverity` use cases are implemented.

pub const LOOP_CONTROL: &str = "/dev/loop-control";

pub const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;
pub const LOOP_CONFIGURE: libc::c_ulong = 0x4C0A;
pub const LOOP_CLR_FD: libc::c_ulong = 0x4C01;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct loop_config {
    pub fd: u32,
    pub block_size: u32,
    pub info: loop_info64,
    pub reserved: [u64; 8],
}

// SAFETY: C struct is safe to be initialized from raw data
unsafe impl DataInit for loop_config {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct loop_info64 {
    pub lo_device: u64,
    pub lo_inode: u64,
    pub lo_rdevice: u64,
    pub lo_offset: u64,
    pub lo_sizelimit: u64,
    pub lo_number: u32,
    pub lo_encrypt_type: u32,
    pub lo_encrypt_key_size: u32,
    pub lo_flags: Flag,
    pub lo_file_name: [u8; LO_NAME_SIZE],
    pub lo_crypt_name: [u8; LO_NAME_SIZE],
    pub lo_encrypt_key: [u8; LO_KEY_SIZE],
    pub lo_init: [u64; 2],
}

// SAFETY: C struct is safe to be initialized from raw data
//unsafe impl DataInit for loop_info64 {}

bitflags! {
  #[derive(Copy, Clone)]
    pub struct Flag: u32 {
        const LO_FLAGS_READ_ONLY = 1 << 0;
        const LO_FLAGS_AUTOCLEAR = 1 << 2;
        const LO_FLAGS_PARTSCAN = 1 << 3;
        const LO_FLAGS_DIRECT_IO = 1 << 4;
    }
}

pub const LO_NAME_SIZE: usize = 64;
pub const LO_KEY_SIZE: usize = 32;
