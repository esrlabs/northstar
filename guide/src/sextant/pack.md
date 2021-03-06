# Packing an NPK

NPKs are created using the `pack` command of `sextant`.
The command requires the following input:

1. a manifest file describing the NPK
2. a root folder containing all files required at runtime

## The Manifest File

The manifest is a YAML file that references all necessary data to mount and execute the container.
An example `manifest.yaml` of the `hello-world` container (found in `examples/hello-world/manifest.yaml`) looks as follows:

```yaml
name: hello-world
version: 0.0.1
init: /hello-world
uid: 1000
gid: 1000
env:
  HELLO: northstar
io:
  stdout:
    log:
      - DEBUG
      - hello
mounts:
    /lib:
      host: /lib
    /lib64:
      host: /lib64
    /system:
      host: /system
```

More details on the manifest format can be found in the chapter
[NPK Format Reference](npk_format_reference.md).

## The `root` Folder

The root folder contains all the container data that will be available during runtime.
This includes executable files as well as additional resources.
During packing, the contents of the folder will be copied to a squashfs image that is then added to the NPK.
This image file will be mounted by the northstar runtime when the container is run.

## Calling `sextant pack`

Let us `pack` the `hello-world` example container under Linux.
First, we build the `hello-world` binary from the northstar directory using cargo:

```bash
$ cargo build --release --bin hello-world
Compiling hello-world v0.1.0 (/home/nori/dev/northstar/examples/hello-world)
Finished release [optimized] target(s) in 2.77s
```

The resulting binary is found in the `target/release` directory:

```bash
$ ls target/release/hello-world
target/release/hello-world
```

Next, we can crate the destination directory if it does not already exist.
We will choose `target/northstar/repository` as our destination as it is the default place where northstar looks for NPKs on startup.
This default is configured in `northstar.toml`.

```bash
$ mkdir -p target/northstar/repository
```

Finally, we are able to call `sextant` and create the NPK:

```bash
$ target/debug/sextant pack \
--manifest examples/hello-world/manifest.yaml \
--root target/release/hello-world \
--out target/northstar/repository
```

The resulting file can be found in the output directory:

```bash
$ ls target/northstar/repository
hello-world-0.0.1.npk
```

## Signing an NPK

NPKs can be signed using ed25519 signatures.
If your runtime is configured to check NPK signatures then containers with missing or invalid signatures will not be accepted.
To create a signed version of our container we have to specify the required private key:

```bash
$ target/debug/sextant pack \
--manifest examples/hello-world/manifest.yaml \
--root target/release/hello-world \
--key ./examples/keys/northstar.key \
--out target/northstar/repository
```

Chapter [Generating Repository Keys](gen_repo_keys.md) describes how to generate keys suitable for signing and verifying NPKs.
