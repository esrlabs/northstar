use std::path::Path;

use futures::TryFutureExt;
use lazy_static::lazy_static;
use log::warn;
use nix::sys::{signal::Signal, wait};

use crate::{
    common::container::Container,
    runtime::{
        error::{Context, Error},
        state::Process,
        ExitStatus, Pid,
    },
};

mod youki;

lazy_static! {
    static ref YOUKI: youki::Youki = youki::Youki::new().expect("Failed to start youki");
}

/// OCI Container Process
#[derive(Debug)]
pub struct OciProcess(youki::Container<'static>);

impl OciProcess {
    /// Creates a new OCI Container process
    pub async fn new(id: Container, bundle: &Path) -> Result<OciProcess, Error> {
        Ok(OciProcess(YOUKI.create(id, bundle).await?))
    }
}

#[async_trait::async_trait]
impl Process for OciProcess {
    /// Return the pid of the process
    async fn pid(&self) -> Pid {
        self.0.pid().await.expect("Failed to get pid")
    }

    async fn spawn(&mut self) -> Result<(), Error> {
        self.0.start().await
    }

    async fn kill(&mut self, signal: Signal) -> Result<(), Error> {
        self.0.kill(signal).await
    }

    async fn wait(&mut self) -> Result<ExitStatus, Error> {
        match self
            .0
            .status()
            .await
            .context("Failed to get container state")?
        {
            youki::Status::Running => {
                // FIXME: This function is currently used during the state shutdown and after the
                // process is signaled with SIGKILL. This will block but it shold not take long.
                let pid = nix::unistd::Pid::from_raw(self.pid().await as i32);
                match wait::waitpid(pid, None) {
                    Ok(wait::WaitStatus::Exited(_pid, code)) => Ok(ExitStatus::Exit(code)),
                    Ok(wait::WaitStatus::Signaled(_pid, signal, _dump)) => {
                        Ok(ExitStatus::Signalled(signal as u8))
                    }
                    _ => panic!("Failed to wait exit status"),
                }
            }
            youki::Status::Stopped => {
                // TODO get the actual exit code?
                Ok(ExitStatus::Exit(0))
            }
            _ => {
                // TODO Handle other states
                unimplemented!()
            }
        }
    }

    async fn destroy(&mut self) -> Result<(), Error> {
        self.0
            .delete(false)
            .or_else(|e| {
                warn!("Failed to delete container: {}", e);
                self.0.delete(true)
            })
            .await
    }
}
