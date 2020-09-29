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

use anyhow::{anyhow, Result};
use async_std::path::Path;
use libc::*;
use std::{ffi::CString, os::unix::ffi::OsStrExt, ptr};

bitflags::bitflags! {
    /// Flags which may be specified when mounting a file system.
    pub struct MountFlags: c_ulong {
        /// Perform a bind mount, making a file or a directory subtree visible at another
        /// point within a file system. Bind mounts may cross file system boundaries and
        /// span chroot(2) jails. The filesystemtype and data arguments are ignored. Up
        /// until Linux 2.6.26, mountflags was also ignored (the bind mount has the same
        /// mount options as the underlying mount point).
        const BIND = MS_BIND;

        /// Make directory changes on this file system synchronous.(This property can be
        /// obtained for individual directories or subtrees using chattr(1).)
        const DIRSYNC = MS_DIRSYNC;

        /// Permit mandatory locking on files in this file system. (Mandatory locking must
        /// still be enabled on a per-file basis, as described in fcntl(2).)
        const MANDLOCK = MS_MANDLOCK;

        /// Move a subtree. source specifies an existing mount point and target specifies
        /// the new location. The move is atomic: at no point is the subtree unmounted.
        /// The filesystemtype, mountflags, and data arguments are ignored.
        const MOVE = MS_MOVE;

        /// Do not update access times for (all types of) files on this file system.
        const NOATIME = MS_NOATIME;

        /// Do not allow access to devices (special files) on this file system.
        const NODEV = MS_NODEV;

        /// Do not update access times for directories on this file system. This flag provides
        /// a subset of the functionality provided by MS_NOATIME; that is, MS_NOATIME implies
        /// MS_NODIRATIME.
        const NODIRATIME = MS_NODIRATIME;

        /// Do not allow programs to be executed from this file system.
        const NOEXEC = MS_NOEXEC;

        /// Do not honor set-user-ID and set-group-ID bits when executing programs from this
        /// file system.
        const NOSUID = MS_NOSUID;

        /// Make this mount point private.  Mount and unmount events do not propagate into or
        /// out of this mount point.
        const PRIVATE = MS_PRIVATE;

        /// Mount file system read-only.
        const RDONLY = MS_RDONLY;

        /// When a file on this file system is accessed, only update the file's last access
        /// time (atime) if the current value of atime is less than or equal to the file's
        /// last modification time (mtime) or last status change time (ctime). This option is
        /// useful for programs, such as mutt(1), that need to know when a file has been read
        /// since it was last modified. Since Linux 2.6.30, the kernel defaults to the behavior
        /// provided by this flag (unless MS_NOATIME was specified), and the MS_STRICTATIME
        /// flag is required to obtain traditional semantics. In addition, since Linux 2.6.30,
        /// the file's last access time is always updated if it is more than 1 day old.
        const RELATIME = MS_RELATIME;

        /// Remount an existing mount. This allows you to change the mountflags and data of an
        /// existing mount without having to unmount and remount the file system. target should
        /// be the same value specified in the initial mount() call; source and filesystemtype
        /// are ignored.
        ///
        /// The following mountflags can be changed: MS_RDONLY, MS_SYNCHRONOUS, MS_MANDLOCK;
        /// before kernel 2.6.16, the following could also be changed: MS_NOATIME and
        /// MS_NODIRATIME; and, additionally, before kernel 2.4.10, the following could also
        /// be changed: MS_NOSUID, MS_NODEV, MS_NOEXEC.
        const REMOUNT = MS_REMOUNT;

        /// Make this mount point shared.  Mount and unmount events immediately under this mount
        /// point will propagate to the other mount points that are members of this mount's peer
        /// group. Propagation here means that the same mount or unmount will automatically occur
        /// under all of the other mount points in the peer group.  Conversely, mount and unmount
        /// events that take place under peer mount points will propagate to this mount point.
        const SHARED = MS_SHARED;

        /// Suppress the display of certain (printk()) warning messages in the kernel log.
        /// This flag supersedes the misnamed and obsolete MS_VERBOSE flag (available
        /// since Linux 2.4.12), which has the same meaning.
        const SILENT = MS_SILENT;

        /// Always update the last access time (atime) when files on this file system are
        /// accessed. (This was the default behavior before Linux 2.6.30.) Specifying this
        /// flag overrides the effect of setting the MS_NOATIME and MS_RELATIME flags.
        const STRICTATIME = MS_STRICTATIME;

        /// Make writes on this file system synchronous (as though the O_SYNC flag to
        /// open(2) was specified for all file opens to this file system).
        const SYNCHRONOUS = MS_SYNCHRONOUS;
    }
}

pub async fn mount(
    source: &Path,
    target: &Path,
    fstype: &str,
    flags: MountFlags,
    data: Option<&str>,
) -> Result<()> {
    let c_source = CString::new(source.as_os_str().as_bytes())?;
    let c_target = CString::new(target.as_os_str().as_bytes())?;
    let fstype = fstype.to_string();
    let data = data.map(|s| s.to_string());
    let c_fstype = CString::new(fstype.as_bytes())?;
    let c_data = data.as_ref().map_or(ptr::null(), |d| d.as_ptr()) as *const c_void;
    let result = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            flags.bits(),
            c_data,
        )
    };

    match result {
        0 => Ok(()),
        _err => Err(anyhow!(
            "Failed to mount: {}",
            std::io::Error::last_os_error()
        )),
    }
}

pub async fn unmount(target: &Path) -> Result<()> {
    let c_target = CString::new(target.as_os_str().as_bytes())?;
    let result = unsafe { libc::umount(c_target.as_ptr()) };

    match result {
        0 => Ok(()),
        _err => Err(anyhow!(
            "Failed to unmount: {}",
            std::io::Error::last_os_error()
        )),
    }
}
