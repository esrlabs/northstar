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

use libc::c_void;
use nix::{
    errno::Errno,
    libc::{self, c_int},
    sched,
    unistd::{self, ForkResult},
};
use sched::CloneFlags;

#[cfg(not(target_os = "android"))]
pub(super) fn clone(flags: CloneFlags, signal: Option<c_int>) -> nix::Result<ForkResult> {
    let combined = flags.bits() | signal.unwrap_or(0);
    let res = unsafe {
        libc::syscall(
            libc::SYS_clone,
            combined,
            std::ptr::null() as *const c_void,
            0u64,
            0u64,
            0u64,
        )
    };

    Errno::result(res).map(|res| match res {
        0 => ForkResult::Child,
        res => ForkResult::Parent {
            child: unistd::Pid::from_raw(res as i32),
        },
    })
}

#[cfg(target_os = "android")]
#[allow(invalid_value)]
pub(super) fn clone(flags: CloneFlags, signal: Option<c_int>) -> nix::Result<ForkResult> {
    use std::{mem::transmute, ptr::null_mut};
    let combined = flags.bits() | signal.unwrap_or(0);
    let res = unsafe {
        libc::clone(
            transmute::<u64, extern "C" fn(*mut c_void) -> c_int>(0u64),
            null_mut(),
            combined,
            null_mut(),
            0u64,
            0u64,
            0u64,
            0u64,
        )
    };

    Errno::result(res).map(|res| match res {
        0 => ForkResult::Child,
        res => ForkResult::Parent {
            child: unistd::Pid::from_raw(res as i32),
        },
    })
}
