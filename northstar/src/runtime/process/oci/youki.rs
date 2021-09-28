use std::{ffi::OsStr, path::Path, process::Output};

use nix::sys::signal::Signal;
use serde::Deserialize;
use tempfile::{tempdir, TempDir};
use tokio::{io::AsyncBufReadExt, process::Command};

use crate::runtime::{
    error::{Context, Error},
    Pid,
};

/// Path to youki binary
///
/// Unfortunately youki does no longer provide a library package. Because cargo does not currenlty
/// support binary dependencies we have to handle youki's binary externally. It is built from the
/// `build.rs` and the result is exported in this environment variable.
const YOUKI_BIN_PATH: &str = env!("YOUKI_BIN_PATH");

/// Wrapper to manage youki containers
#[derive(Debug)]
pub struct Youki {
    /// Path to the temporal directory with the container states
    state_dir: TempDir,
}

impl<'a> Youki {
    /// Creates an instance of youki that uses a temporal directory to store the container states
    pub fn new() -> Result<Youki, Error> {
        let state_dir = tempdir().context("Failed to create temporal directory")?;
        Ok(Youki { state_dir })
    }

    /// Create a new youki container
    pub async fn create<T: ToString>(
        &'a self,
        id: T,
        bundle: &Path,
    ) -> Result<Container<'a>, Error> {
        let id = id.to_string();

        let console_path = self.state_dir.path().join(format!("{}_socket", id));
        let receiver = pty::ReceivePtyMaster::new(console_path.clone())?;
        let pty_fd = { tokio::task::spawn(async move { receiver.receive().await }) };

        self.run_with_args(&[
            OsStr::new("create"),
            OsStr::new("--bundle"),
            bundle.as_os_str(),
            OsStr::new("--console-socket"),
            console_path.as_os_str(),
            id.as_ref(),
        ])
        .await
        .context("Failed to create container")?;

        let output = pty_fd
            .await
            .context("Failed to receive pty file descriptor")??;

        // Spawn a task that prints the process standard output
        tokio::task::spawn(async move {
            let buf_reader = tokio::io::BufReader::new(output);
            let mut lines = buf_reader.lines();

            // read each line and print it
            while let Ok(Some(line)) = lines.next_line().await {
                log::debug!("{}", line);
            }
        });

        Ok(Container { youki: self, id })
    }

    /// Runs youki with the input commands
    async fn run_with_args<I, S>(&self, args: I) -> std::io::Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let stdout = Command::new(YOUKI_BIN_PATH)
            .arg("--root")
            .arg(self.state_dir.as_ref())
            .args(args)
            .output()
            .await;
        match &stdout {
            Ok(output) => {
                let stdout = std::str::from_utf8(&output.stdout).unwrap();
                let stderr = std::str::from_utf8(&output.stderr).unwrap();

                for line in stdout.lines() {
                    log::debug!("youki stdout: {}", line);
                }
                for line in stderr.lines() {
                    log::debug!("youki stderr: {}", line);
                }
            }
            Err(err) => {
                log::warn!("youki err: {}", err);
            }
        }
        stdout
    }
}

/// Youki Container
#[derive(Debug)]
pub struct Container<'a> {
    youki: &'a Youki,
    id: String,
}

/// Container State
#[derive(Deserialize)]
struct State {
    status: Status,
    pid: u32,
}

/// Container status
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Creating,
    Created,
    Running,
    Paused,
    Stopped,
}

impl<'a> Container<'a> {
    pub async fn start(&self) -> Result<(), Error> {
        self.youki
            .run_with_args(&["start", &self.id])
            .await
            .context("Failed to start container")
            .map(drop)
    }

    pub async fn kill(&self, signal: Signal) -> Result<(), Error> {
        self.youki
            .run_with_args(&["kill", &self.id, signal.as_str()])
            .await
            .context("Failed to kill container")
            .map(drop)
    }

    pub async fn status(&self) -> Result<Status, Error> {
        self.state().await.map(|state| state.status)
    }

    /// Returns the container PID
    pub async fn pid(&self) -> Result<Pid, Error> {
        self.state().await.map(|state| state.pid)
    }

    /// Deletes the container
    pub async fn delete(&self, force: bool) -> Result<(), Error> {
        let cmd = if force {
            vec!["delete", "-f", &self.id]
        } else {
            vec!["delete", &self.id]
        };

        self.youki
            .run_with_args(cmd.into_iter())
            .await
            .map(drop)
            .context("Failed to delete contaner")
    }

    async fn state(&self) -> Result<State, Error> {
        let output = self
            .youki
            .run_with_args(&["state", &self.id])
            .await
            .context("Failed to kill container")?
            .stdout;

        serde_json::from_slice(output.as_slice()).context("Failed to parse container state")
    }
}

mod pty {
    use std::{
        fs,
        os::unix::{
            io::{AsRawFd, FromRawFd},
            prelude::RawFd,
        },
        path::PathBuf,
    };

    use log::warn;
    use nix::{
        cmsg_space,
        sys::{socket, uio::IoVec},
    };
    use tokio::{fs::File, net::UnixListener};

    use super::*;

    /// Receive a PTY master over the provided unix socket
    pub struct ReceivePtyMaster {
        console_socket: PathBuf,
        listener: UnixListener,
    }

    impl ReceivePtyMaster {
        /// Bind a unix domain socket to the provided path
        pub fn new(console_socket: PathBuf) -> Result<Self, Error> {
            let listener = UnixListener::bind(&console_socket).context("Failed to bind socket")?;
            Ok(Self {
                console_socket,
                listener,
            })
        }

        /// Receive a master PTY file descriptor from the socket
        pub async fn receive(self) -> Result<File, Error> {
            let (console_stream, _a) = self
                .listener
                .accept()
                .await
                .context("Failed to get socke connection")?;

            loop {
                console_stream
                    .readable()
                    .await
                    .context("Failed to wait on readable socket")?;

                let mut buf = [0u8; 4096];
                let iov = [IoVec::from_mut_slice(&mut buf)];
                let mut cmsgspace = cmsg_space!([RawFd; 1]);

                let console_stream_fd = console_stream.as_raw_fd();
                let msg = nix::sys::socket::recvmsg(
                    console_stream_fd,
                    &iov,
                    Some(&mut cmsgspace),
                    socket::MsgFlags::empty(),
                )
                .context("pty socket recvmsg")?;

                for cmsg in msg.cmsgs() {
                    if let socket::ControlMessageOwned::ScmRights(fds) = cmsg {
                        return Ok(unsafe { File::from_raw_fd(fds[0]) });
                    } else {
                        continue;
                    }
                }
            }
        }
    }

    impl Drop for ReceivePtyMaster {
        fn drop(&mut self) {
            if let Err(e) = fs::remove_file(&self.console_socket) {
                warn!("Failed to clean up console socket: {}", e);
            }
        }
    }
}
