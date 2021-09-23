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
