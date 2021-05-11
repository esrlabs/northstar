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

use nix::{
    errno::Errno,
    libc::{self, c_int, pid_t},
    sched,
    unistd::{self, ForkResult},
};
use sched::CloneFlags;
use std::ptr::null_mut;

#[cfg(not(target_os = "android"))]
pub(super) fn clone(
    mut flags: CloneFlags,
    signal: Option<c_int>,
    parent_tid: Option<&mut pid_t>,
) -> nix::Result<ForkResult> {
    let result = if let Some(parent_tid) = parent_tid {
        flags |= CloneFlags::CLONE_PARENT_SETTID;
        let combined = flags.bits() | signal.unwrap_or(0);
        unsafe {
            libc::syscall(
                libc::SYS_clone,
                combined,
                null_mut::<u64>(),
                parent_tid as *mut _,
            )
        }
    } else {
        let combined = flags.bits() | signal.unwrap_or(0);
        unsafe { libc::syscall(libc::SYS_clone, combined, null_mut::<u64>()) }
    };

    Errno::result(result).map(|res| match res {
        0 => ForkResult::Child,
        result => ForkResult::Parent {
            child: unistd::Pid::from_raw(result as i32),
        },
    })
}

#[cfg(target_os = "android")]
#[allow(invalid_value)]
pub(super) fn clone(
    mut flags: CloneFlags,
    signal: Option<c_int>,
    parent_tid: Option<&mut pid_t>,
) -> nix::Result<ForkResult> {
    use std::{mem::transmute, ptr::null_mut};

    let result = if let Some(parent_tid) = parent_tid {
        flags |= CloneFlags::CLONE_PARENT_SETTID;
        let combined = flags.bits() | signal.unwrap_or(0);
        unsafe {
            libc::clone(
                transmute::<u64, extern "C" fn(*mut c_void) -> c_int>(0u64),
                null_mut(),
                combined,
                null_mut(),
                parent_tid as *mut _,
            )
        }
    } else {
        let combined = flags.bits() | signal.unwrap_or(0);
        unsafe {
            libc::clone(
                transmute::<u64, extern "C" fn(*mut c_void) -> c_int>(0u64),
                null_mut(),
                combined,
                null_mut(),
            )
        }
    };

    Errno::result(result).map(|res| match res {
        0 => ForkResult::Child,
        result => ForkResult::Parent {
            child: unistd::Pid::from_raw(result as i32),
        },
    })
}
