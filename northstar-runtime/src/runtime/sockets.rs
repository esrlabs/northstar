use anyhow::{Context, Result};
use itertools::Itertools;
use log::debug;
use nix::sys::{
    socket,
    socket::{AddressFamily, SockFlag, SockType, UnixAddr},
};
use std::{
    collections::HashMap,
    os::fd::{FromRawFd, OwnedFd},
    path::{Path, PathBuf},
};
use tokio::fs;

use crate::{
    common::{container::Container, non_nul_string::NonNulString},
    npk::manifest::socket::{Socket, Type},
};

/// Socket set.
#[derive(Debug)]
pub(crate) struct Sockets {
    /// Parent directory of sockets.
    dir: PathBuf,
}

impl Sockets {
    pub async fn destroy(self) {
        if self.dir.exists() {
            debug!("Removing socket directory {}", self.dir.display());
            fs::remove_dir_all(self.dir).await.ok();
        }
    }
}

/// Open unix sockets for a container.
pub(crate) async fn open(
    socket_dir: &Path,
    container: &Container,
    socket_configuration: &HashMap<NonNulString, Socket>,
) -> Result<(Vec<OwnedFd>, Sockets)> {
    let mut fds = Vec::with_capacity(socket_configuration.len());
    let dir = socket_dir.join(container.name().as_ref());

    if !socket_configuration.is_empty() && !dir.exists() {
        debug!("Creating socket directory for {container}");
        fs::create_dir_all(&dir).await?;
    }

    for (name, socket_config) in socket_configuration
        .iter()
        .sorted_by_key(|(name, _)| name.as_str())
    {
        let ty = &socket_config.r#type;
        let path = dir.join(name);

        if path.exists() {
            fs::remove_file(&path)
                .await
                .context("failed to remove stale socket")?;
        }

        let r#type = match ty {
            Type::Stream => SockType::Stream,
            Type::Datagram => SockType::Datagram,
            Type::SeqPacket => SockType::SeqPacket,
        };

        let socket = socket::socket(AddressFamily::Unix, r#type, SockFlag::empty(), None)
            .context("failed to create socket")?;

        debug!("Created socket {name} ({}) for {container}", socket);

        let addr = UnixAddr::new(&path).context("invalid unix path")?;
        debug!("Binding socket {name} for {container} ({ty})",);
        socket::bind(socket, &addr).context("failed to bind")?;

        // Streaming and seqpacket sockets need to be listened on.
        if matches!(ty, Type::Stream | Type::SeqPacket) {
            socket::listen(socket, 100).context("failed to listen")?;
        }

        let socket = unsafe { OwnedFd::from_raw_fd(socket) };
        fds.push(socket);
    }

    Ok((fds, Sockets { dir }))
}
