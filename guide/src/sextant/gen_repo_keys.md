# Generating Repository Keys

To sign NPKs using `sextant` we first have to have a suitable key pair.
This can be generated using the `sextant gen-key` command.
The following call creates a new key pair called `repokey` in the current directory:

```bash
target/debug/sextant gen-key --name repokey --out .
```

After the call we can see that two files were created:

```bash
$ ls | grep repokey
repokey.key
repokey.pub
```

The private key `repokey.key` can be used for signing of NPKs (see [Packing an NPK](pack.md)).
The public key `repokey.pub` can be used by the northstar runtime to verify NPKs.
