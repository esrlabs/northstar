# Sextant - A tool for working with northstar NPK containers

Northstar containers are distributed in the NPK file format.

An NPK file contains both the container's application logic and the data files
necessary to mount and run the container.  To facilitate the creation,
inspection and modification of NPKs, northstar provides the `northstar-sextant`
CLI tool.

## Packing an unsigned NPK

NPKs are created (packed) using the `pack` command of `northstar-sextant`.
It requires the following input:

1. A manifest file describing the NPK.
2. A root folder containing the files required at runtime.

During packing, the contents of the folder will be copied to a squashfs image
that will be mounted by the northstar runtime when the container is run.

For example, the following command packs the `hello-world` example container:

```bash
$ target/debug/northstar-sextant pack \
--manifest examples/container/hello-world/manifest.yaml \
--root target/release/hello-world \
--out target/northstar/repository
```

The output of `northstar-sextant pack` is single NPK file:

```bash
$ ls target/northstar/repository
hello-world-0.0.1.npk
```

## Packing a signed NPK

NPKs can be signed using [Ed25519](https://ed25519.cr.yp.to/) signatures.  If
your runtime is configured to check NPK signatures, containers with missing or
invalid signatures will be rejected.  To pack a signed version of the
`hello-world` example container, a private key has to be provided:

```bash
$ target/debug/northstar-sextant pack \
--manifest examples/container/hello-world/manifest.yaml \
--root target/release/hello-world \
--key ./examples/keys/northstar.key \
--out target/northstar/repository
```

## Generating repository keys

To sign NPKs using `northstar-sextant` a suitable key pair is needed.  It can be
generated using the `northstar-sextant gen-key` command.  The following call
creates a new key pair (`repokey.key` and `repokey.pub`) in the current
directory:

```bash
target/debug/northstar-sextant gen-key --name repokey --out .
```

The private key `repokey.key` can be used for signing of NPKs while the public
key `repokey.pub` is used by the northstar runtime to verify NPKs.

## Unpacking an NPK

NPKs are ZIP files that contain among other things a squashfs image that will be
mounted at runtime.  To extract both the outer ZIP and the inner image, the
`unpack` command of `northstar-sextant` can be used.

To unpack the `hello-world` example container, the `northstar-sextant unpack`
can be used:

```sh
$ target/debug/northstar-sextant unpack \
--npk ./target/northstar/repository/hello-world-0.0.1.npk \
--out ./hello-world-container
```

The extracted container can be found in the output directory:

```sh
$ ls hello-world-container
fs.img  manifest.yaml  signature.yaml  squashfs-root
```

The `squashfs-root` directory holds the extracted contents of the `fs.img`
squashfs image:

```sh
$ ls hello-world-container/squashfs-root/
dev  hello-world  lib  lib64  proc  system
```

We can see the `hello-world` binary as well as the empty mount points mentioned
in the `manifest.yaml`.

## Inspecting an NPK

To get information about an already packed NPK `northstar-sextant` provides the
`inspect` command.

### Inspecting an NPK with default settings

Inspecting an NPK without any additional parameters will show the following information:

- List of files contained in the NPK
- Content of manifest.yaml
- Content of signature.yaml
- List of files contained in the compressed squashfs image (`fs.img`) stored in
  the NPK

The `hello-world` example container can be inspected with the following command:

```sh
$ northstar-sextant inspect target/northstar/repository/hello-0.0.1.npk
...
```

### Inspecting an NPK with the `--short` parameter

To facilitate the inspection of many containers as part of scripts, the
`inspect` command features the `--short` parameter.  It condenses the inspection
output into a single line with the following information:

- Container name
- Container version
- NPK format version
- Whether this is a resource container

Inspecting the `hello-world` example container with the `--short` flag gives the
following output:

```markdown
$ northstar-sextant inspect --short hello-world-0.0.1.npk 
name: hello-world, version: 0.0.1, NPK version: 0.0.2, resource container: no
```
