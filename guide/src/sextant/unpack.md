# Unpacking an NPK

NPKs are ZIP files that contain among other things a squashfs image that will be mounted at runtime.
To extract both the outer ZIP and the inner image, the `unpack` command of `sextant` can be used.

To unpack the `hello` container we packed in the chapter [Packing an NPK](pack.md) we first create an output directory for the extracted contents:

```bash
$ mkdir hello_container
```

Next, we call `sextant unpack`:

```bash
$ target/debug/sextant unpack \
--npk ./target/northstar/repository/hello-0.0.1.npk \
--out ./hello_container
```

The extracted container can be found in the directroy we created:

```bash
$ ls hello_container
fs.img  manifest.yaml  signature.yaml  squashfs-root
```

As we can see, a `squashfs-root` directory was created.
It contains the extracted contents of the `fs.img` squashfs image:

```bash
$ ls hello_container/squashfs-root/
dev  hello  lib  lib64  proc  system
```

We can see the `hello` binary as well as the empty mount points mentioned in the `manifest.yaml`.
