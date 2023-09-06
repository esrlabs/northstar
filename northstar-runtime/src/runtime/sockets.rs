use anyhow::{Context, Result};
use itertools::Itertools;
use log::debug;
use nix::{
    sys::{
        socket,
        socket::{sockopt, AddressFamily, SockFlag, SockType, UnixAddr},
    },
    unistd::{fchown, Gid, Uid},
};
use std::{
    collections::HashMap,
    fs::Permissions,
    os::unix::prelude::*,
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
    sockets: Vec<PathBuf>,
}

impl Sockets {
    pub async fn destroy(self) {
        for socket in self.sockets {
            debug!("Removing socket {}", socket.display());
            fs::remove_file(socket)
                .await
                .expect("failed to remove socket");
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
    let mut sockets = Vec::with_capacity(socket_configuration.len());

    for (name, descriptor) in socket_configuration
        .iter()
        .sorted_by_key(|(name, _)| name.as_str())
        .map(|(name, descriptor)| {
            (
                format!("{}:{}:{name}", container.name(), container.version()),
                descriptor,
            )
        })
    {
        let ty = &descriptor.r#type;
        let path = socket_dir.join(&name);

        // Remove stale sockets.
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

        debug!("Creating socket {name}");
        let socket = socket::socket(AddressFamily::Unix, r#type, SockFlag::empty(), None)
            .context("failed to create socket")?;

        if descriptor.passcred == Some(true) {
            debug!("Setting SO_PASSCRED on socket {name}");
            socket::setsockopt(&socket, sockopt::PassCred, &true)
                .context("failed to set SO_PASSCRED")?;
        }

        let addr = UnixAddr::new(&path).context("invalid unix path")?;
        debug!("Binding socket {name} ({ty})",);
        socket::bind(socket.as_raw_fd(), &addr).context("failed to bind")?;

        // Streaming and seqpacket sockets need to be listened on.
        if matches!(ty, Type::Stream | Type::SeqPacket) {
            socket::listen(&socket, 100).context("failed to listen")?;
        }

        debug!(
            "Setting socket mode {} on {name}",
            umask::Mode::from(descriptor.mode)
        );
        fs::set_permissions(&path, Permissions::from_mode(descriptor.mode)).await?;

        sockets.push(path);

        if descriptor.uid.is_some() || descriptor.gid.is_some() {
            debug!(
                "Setting socket ownership {}:{} on {name}",
                descriptor.uid.map(|d| d.to_string()).unwrap_or("-".into()),
                descriptor.gid.map(|d| d.to_string()).unwrap_or("-".into()),
            );
            fchown(
                socket.as_raw_fd(),
                descriptor.uid.map(Uid::from_raw),
                descriptor.gid.map(Gid::from_raw),
            )
            .context("failed to set socket ownership")?;
        }

        fds.push(socket);
    }

    Ok((fds, Sockets { sockets }))
}
