# NPK Format Reference

NPKs are compressed archives containing both the container's application logic as well as the data files necessary to mount an run the container.

Internally, an NPK consist of three files:

- manifest.yaml
- signature.yaml
- fs.img

## Manifest.yaml

The file `manifest.yaml` references all data necessary to mount and execute the container.
As an example, the `manifest.yaml` of the `memeater` example container looks as follows:

```yaml
{{#include ./../../../examples/container/memeater/manifest.yaml}}
```

### `name`

The name of the container
Example:

```yaml
name: hello
```

### `version`

The version of the container
Example:

```yaml
version: 0.0.1
```

### `init`

The binary executed when the container is run
Example:

```yaml
init: /hello
```

### `args` (optional)

Additional arguments for the application invocation
Example:

```yaml
args:
  - /message/hello
```

### `uid`

The user ID used to mount the container
Example:

```yaml
uid: 1000
```

### `gid`

The group ID used to mount the container
Example:

```yaml
gid: 1000
```

### `env`

List of additional environment variables and their values
Example:

```yaml
env:
  RUST_BACKTRACE: 1
  ```

### `autostart`

Whether or not this container should be run upon northstar startup
Example:

```yaml
autostart: true
```

### `cgroups`

CGroup configuration
Examples:

```yaml
cgroups:
  cpu:
    shares: 100
```

```yaml
cgroups:
  memory:
    limit_in_bytes: 10000000
    swappiness: 0
```

### `seccomp` (optional)

SecComp configuration
Example:

Example:

```yaml
seccomp:
  clone: 1
  mmap: arg2 in ~PROT_EXEC || arg2 in ~PROT_WRITE
  prctl: 1
  munmap: 1
  mprotect: arg2 in ~PROT_EXEC || arg2 in ~PROT_WRITE
  futex: 1
  openat: 1
  close: 1
  execve: 1
```

### `mounts`

List of bind mounts and resources
Example:

```yaml
mounts:
    /lib:
      host: /lib
    /lib64:
      host: /lib64
    /system:
      host: /system
```

### `capabilities` (optional)

String containing capability names to give to new container
Example:

```yaml
capabilities:
  - cap_net_raw
```

### `suppl_groups` (optional)

String containing group names to give to new container
Example:

```yaml
suppl_groups:
  - inet
```

### `io` (optional)

Input/Output configuration
Example:

```yaml
io:
  stdout:
    log:
      - DEBUG
      - hello
```

## Signature.yaml

The file `signature.yaml` contains the hash of `manifest.yaml` and both hash and dm-verity information of the squashfs image `fs.img`.
If the NPK is signed, a second entry in `signature.yaml` references the name of the key used to sign the NPK as well as the base64 encoded signature of the verity hash.

An example `signature.yaml` looks as follows:

```yaml
manifest.yaml:
  hash: ee5967e740febb3a1e018e189ed21412f8bf71d34bea7b506f709d37984e90cc
fs.img:
  hash: 35d1a25870a2bf25328a250243972b931e220057cc2d0fe998aef163ea59142e
  verity-hash: f14909e6b8e6ca919f9086d54089feed49053f1e590a6f2dccad171960686eff
  verity-offset: 397312
---
key: northstar
signature: aDnKZ8JQ5tegOqKM2TW/ULU2DAlcVG7ieyS0ZaDGnRHT5Yggcgog5QbD0ZnTyGIFY8bo0+lToQu+BcK2XA35BA==
```

## Ressource Containers

Containers without an `init` field in their `manifest.yaml` are called **Ressource Containers**.
They are useful to provide common data to other containers.
To add a reference to a resources container, we have to add an entry in the `mount` field of manifest of the referencing container.

For example, the `ferris_says_hello` container references the `hello_message` container which provides a required string:

```yaml
mounts:
  /bin:
    resource: "ferris:0.0.1/"
  /lib64:
    host: /lib64
  /lib:
    host: /lib
  /system:
    host: /system
  /message:
    resource: "hello_message:0.0.1/"
```
