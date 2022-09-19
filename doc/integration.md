# Integration Notes

## Portability

Northstar makes extensive use of Linux Kernel features and runs on Linux systems
*only*. Northstar build and runs for/on:

* `aarch64-linux-android`
* `aarch64-unknown-linux-gnu`
* `aarch64-unknown-linux-musl`
* `x86_64-unknown-linux-gnu`

Northstar requires a 64bit system.

### Kernel features

Northstar requires certain features enabled in the Linux Kernel of the host system:

#### File sytems and device mapper

* CONFIG_BLK_DEV_DM
* CONFIG_BLK_DEV_LOOP
* CONFIG_CRYPTO_SHA256
* CONFIG_DM_CRYPT
* CONFIG_DM_VERITY
* CONFIG_SQUASHFS
* CONFIG_TMPFS (optional)

SquashFS can be tuned in various ways. Northstar just requires the following
squashfs driver option:

* CONFIG_SQUASHFS_XATTR

 Northstar doesn't care about the other [squashfs
 options](https://elixir.bootlin.com/linux/latest/source/fs/squashfs/Kconfig).
 Please tune the `squashfs` options to your needs. Defaults probably result in
 bad performance.  You have been warned.

Check the number of configured loop devices in `CONFIG_BLK_DEV_LOOP_MIN_COUNT`

#### CGroups

CGroups (except the memory controlelr) are optional. Ensure at least:

* CONFIG_CGROUPS
* CONFIG_MEMCG

#### Namespaces

Northstar makes use of the following namespace types:

* CONFIG_UTS_NS
* CONFIG_PID_NS
* CONFIG_NET_NS
* CONFIG_IPC_NS

### Runtime permissions

The Northstar runtime requires privileged rights on the host system. The rights
can be granted either by running Northstar as `root` *or* ensure the following
list of
[capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html):

* `cap_chown`: change ownership of container directories
* `cap_dac_override`: lazy workaround for permissions on `/dev/mapper/control`
  and `cgroups`. *Do not use this in production!*
* `cap_kill`: send signals to container inits
* `cap_setgid`: supplementary groups
* `cap_setpcap`: drop capabilities
* `cap_setuid`: user id
* `cap_sys_admin`: `mount`, `umount`, `setns`
* `cap_sys_resource`: increase `rlimits` (init)

### Runtime binary storage must be ready only and verified

It is highly recommended to use a *read only* storage option for the northstar
runtime binary. It is highly recommended to protect the storage that hosts the
runtime binary with some kind of integrity verification e.g `device mapper
verity`. Using the Northstar runtime binary from a write enabled location, the
binary can be modified under certain conditions. See
[#787](https://github.com/esrlabs/northstar/issues/787) for details.
