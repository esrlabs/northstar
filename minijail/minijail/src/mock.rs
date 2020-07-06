// Copyright (c) 2020 E.S.R.Labs. All rights reserved.
//
// NOTICE:  All information contained herein is, and remains
// the property of E.S.R.Labs and its suppliers, if any.
// The intellectual and technical concepts contained herein are
// proprietary to E.S.R.Labs and its suppliers and may be covered
// by German and Foreign Patents, patents in process, and are protected
// by trade secret or copyright law.
// Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained
// from E.S.R.Labs.

use anyhow::{Context, Result};
use libc::pid_t;
use std::{
    os::{raw::c_ulong, unix::io::RawFd},
    path::{Path, PathBuf},
};

pub enum LogPriority {
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Default)]
pub struct Minijail {
    chroot: Option<PathBuf>,
    bind_mounts: Vec<(PathBuf, PathBuf)>,
}

impl Minijail {
    /// Creates a new jail configuration.
    pub fn new() -> Result<Minijail> {
        Ok(Minijail::default())
    }
    pub fn log_to_fd(&self, _fd: RawFd, _priority: LogPriority) {}
    pub fn change_uid(&mut self, _uid: libc::uid_t) {}
    pub fn change_gid(&mut self, _gid: libc::gid_t) {}
    pub fn set_supplementary_gids(&mut self, _ids: &[libc::gid_t]) {}
    pub fn keep_supplementary_gids(&mut self) {}
    pub fn set_rlimit(
        &mut self,
        _kind: libc::c_int,
        _cur: libc::rlim_t,
        _max: libc::rlim_t,
    ) -> Result<()> {
        Ok(())
    }
    pub fn use_seccomp(&mut self) {}
    pub fn no_new_privs(&mut self) {}
    pub fn use_seccomp_filter(&mut self) {}
    pub fn set_seccomp_filter_tsync(&mut self) {}
    pub fn parse_seccomp_program(&mut self, _path: &Path) -> Result<()> {
        Ok(())
    }
    pub fn parse_seccomp_filters(&mut self, _path: &Path) -> Result<()> {
        Ok(())
    }
    pub fn log_seccomp_filter_failures(&mut self) {}
    pub fn use_caps(&mut self, _capmask: u64) {}
    pub fn capbset_drop(&mut self, _capmask: u64) {}
    pub fn set_ambient_caps(&mut self) {}
    pub fn reset_signal_mask(&mut self) {}
    pub fn run_as_init(&mut self) {}
    pub fn namespace_pids(&mut self) {}
    pub fn namespace_user(&mut self) {}
    pub fn namespace_user_disable_setgroups(&mut self) {}
    pub fn namespace_vfs(&mut self) {}
    pub fn new_session_keyring(&mut self) {}
    pub fn skip_remount_private(&mut self) {}
    pub fn namespace_ipc(&mut self) {}
    pub fn namespace_net(&mut self) {}
    pub fn namespace_cgroups(&mut self) {}
    pub fn remount_proc_readonly(&mut self) {}
    pub fn set_remount_mode(&mut self, _mode: c_ulong) {}
    pub fn uidmap(&mut self, _uid_map: &str) -> Result<()> {
        Ok(())
    }
    pub fn gidmap(&mut self, _gid_map: &str) -> Result<()> {
        Ok(())
    }
    pub fn inherit_usergroups(&mut self) {}
    pub fn use_alt_syscall(&mut self, _table_name: &str) -> Result<()> {
        Ok(())
    }
    pub fn enter_chroot(&mut self, dir: &Path) -> Result<()> {
        self.chroot = Some(PathBuf::from(dir));
        Ok(())
    }
    pub fn enter_pivot_root(&mut self, _dir: &Path) -> Result<()> {
        Ok(())
    }
    pub fn mount(&mut self, _src: &Path, _dest: &Path, _fstype: &str, _flags: usize) -> Result<()> {
        unimplemented!()
    }
    pub fn mount_with_data(
        &mut self,
        _src: &Path,
        _dest: &Path,
        _fstype: &str,
        _flags: usize,
        _data: &str,
    ) -> Result<()> {
        Ok(())
    }
    pub fn mount_dev(&mut self) {}
    pub fn mount_tmp(&mut self) {}
    pub fn mount_tmp_size(&mut self, _size: usize) {}
    pub fn mount_bind(&mut self, src: &Path, dest: &Path, _writable: bool) -> Result<()> {
        self.bind_mounts
            .push((PathBuf::from(src), PathBuf::from(dest)));
        Ok(())
    }
    pub fn run(
        &self,
        cmd: &Path,
        _inheritable_fds: &[RawFd],
        args: &[&str],
        env: &[&str],
    ) -> Result<pid_t> {
        let cmd = if let Some(mut chroot) = self.chroot.clone() {
            chroot.push(cmd.strip_prefix("/")?);
            chroot
        } else {
            cmd.to_path_buf()
        };

        let mut cmd = std::process::Command::new(&cmd);
        cmd.args(args);
        let env = env
            .iter()
            .map(|e| {
                let mut s = e.split('=');
                (s.next().unwrap(), s.next().unwrap())
            })
            .collect::<Vec<(&str, &str)>>();
        cmd.envs(env);
        let child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn {:?}", cmd))?;

        Ok(child.id() as i32)
    }
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn fork(&self, _inheritable_fds: Option<&[RawFd]>) -> Result<pid_t> {
        unimplemented!()
    }
}
