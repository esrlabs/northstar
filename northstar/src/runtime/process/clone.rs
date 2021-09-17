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
    libc::{self, c_int},
    sched,
    unistd::{self, ForkResult},
};
use sched::CloneFlags;
use std::ptr::null_mut;

pub(super) fn clone(flags: CloneFlags, signal: Option<c_int>) -> nix::Result<ForkResult> {
    let combined = flags.bits() | signal.unwrap_or(0);
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone,
            combined,
            null_mut::<u32>(),
            null_mut::<u32>(),
            null_mut::<u32>(),
            null_mut::<u32>(),
        )
    };

    Errno::result(result).map(|res| match res {
        0 => ForkResult::Child,
        result => ForkResult::Parent {
            child: unistd::Pid::from_raw(result as i32),
        },
    })
}
