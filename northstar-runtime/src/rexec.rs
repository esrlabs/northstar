use anyhow::{Context, Result};
use memfd::FileSeal;
use nix::unistd::fexecve;
use std::{env, ffi::CString, fs, io, io::Seek, os::unix::prelude::AsRawFd};

/// Path to exe
const EXE: &str = "/proc/self/exe";

/// Expected and applied seals
const SEALS: &[FileSeal] = &[
    FileSeal::SealShrink,
    FileSeal::SealGrow,
    FileSeal::SealWrite,
    FileSeal::SealSeal,
];

/// Replace /proc/self/exe with a sealed memfd.
/// See https://github.com/lxc/lxc/commit/6400238d08cdf1ca20d49bafb85f4e224348bf9d
/// This is *not* needed if the runtime binary is launched from a secured read
/// only storage.
/// This is what happens on syscall level:
/// ```raw
/// openat(AT_FDCWD, "/proc/self/exe", O_RDONLY|O_CLOEXEC) = 3
/// fcntl(3, F_GET_SEALS)                   = -1 EINVAL (Invalid argument)
/// readlink("/proc/self/exe", "..../target/deb"..., 256) = 44
/// memfd_create(".../target/debug/northstar", MFD_CLOEXEC|MFD_ALLOW_SEALING) = 4
/// statx(0, NULL, AT_STATX_SYNC_AS_STAT, STATX_ALL, NULL) = -1 EFAULT (Bad address)
/// statx(3, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, {stx_mask=STATX_ALL|STATX_MNT_ID, stx_attributes=0, stx_mode=S_IFREG|0755, stx_size=186484088, ...}) = 0
/// copy_file_range(-1, NULL, -1, NULL, 1, 0) = -1 EBADF (Bad file descriptor)
/// copy_file_range(3, NULL, 4, NULL, 1073741824, 0) = 186484088
/// copy_file_range(3, NULL, 4, NULL, 1073741824, 0) = 0
/// lseek(4, 0, SEEK_SET)                   = 0
/// fcntl(4, F_ADD_SEALS, F_SEAL_SHRINK)    = 0
/// fcntl(4, F_ADD_SEALS, F_SEAL_GROW)      = 0
/// fcntl(4, F_ADD_SEALS, F_SEAL_WRITE)     = 0
/// fcntl(4, F_ADD_SEALS, F_SEAL_SEAL)      = 0
/// execveat(4, "", ["./target/debug/northstar"], 0x55ae51a95ed0 /* 18 vars */, AT_EMPTY_PATH) = 0
/// ```
pub fn rexec() -> Result<()> {
    let exe = fs::File::open(EXE).context("failed to open exe")?;

    // Check if `exec` is a memfd - if yes we're already a clone.
    match memfd::Memfd::try_from_file(exe) {
        Ok(memfd) => {
            // Compare the seals with the set of expected ones.
            assert_eq!(
                memfd.seals().context("failed to get exe seals")?,
                SEALS.iter().cloned().collect()
            );
            Ok(())
        }
        Err(exe) => {
            let exe_name = env::current_exe().context("failed to get path of current exe")?;
            let memfd = memfd::MemfdOptions::default()
                .allow_sealing(true)
                .close_on_exec(true)
                .create(exe_name.display().to_string())
                .context("failed to create memfd")?;

            let mut exe = io::BufReader::new(exe);
            io::copy(&mut exe, &mut memfd.as_file()).context("failed to copy exe")?;
            memfd
                .as_file()
                .seek(std::io::SeekFrom::Start(0))
                .context("failed to seek")?;
            SEALS
                .iter()
                .try_for_each(|seal| memfd.add_seal(*seal))
                .context("failed to add seal")?;

            let args = env::args()
                .map(CString::new)
                .collect::<Result<Vec<_>, _>>()
                .context("failed to convert arg")?;
            let env: Vec<_> = env::vars()
                .map(|(k, v)| format!("{}={}", k, v))
                .map(CString::new)
                .collect::<Result<Vec<_>, _>>()
                .context("failed to convert env")?;
            panic!("{:?}", fexecve(memfd.as_raw_fd(), &args, &env));
        }
    }
}
