# Inspecting an NPK

To get information about an already packed NPK `northstar-sextant` provides the `inspect`
command.

## Inspecting an NPK with Default Settings

Inspecting an NPK without any additional parameters will show the following information:

- Listing of files contained in the NPK
- Contents of manifest.yaml
- Contents of signature.yaml
- Listing of files contained in the compressed squashfs image (`fs.img`) within the
  NPK

For example, inspecting the `hello-world` example container gives the following output:

```markdown
$ northstar-sextant inspect target/northstar/repository/hello-0.0.1.npk 
# inspection of 'target/northstar/repository/hello-0.0.1.npk'
## NPK Content
signature.yaml
manifest.yaml
fs.img

## manifest.yaml
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

## signature.yaml

```yaml
manifest.yaml:
  hash: ee5967e740febb3a1e018e189ed21412f8bf71d34bea7b506f709d37984e90cc
fs.img:
  hash: bd280a499a46d43dade55de78fc5d87f65c3750c851e95aed448066564a3230a
  verity-hash: 85758440ccc506cd0e73f541443fdf76eae34600dfd04c6d440b50a598fec57f
  verity-offset: 397312
---
key: northstar
signature: xK0f6gIqaarM8FTbhT/qnhSy4ROK8MsoluA2A6kpDCJaAvoea/41j3tY0c047OUL5f/wmnvqrHGyVQ5rr5rKDw==
```

## SquashFS listing

```bash
Parallel unsquashfs: Using 32 processors
1 inodes (11 blocks) to write

drwxr-xr-x user/user                89 2021-03-01 10:15 squashfs-root
dr--r--r-- user/user                 3 2021-03-01 10:15 squashfs-root/dev
-rwxr-xr-x user/user           1315816 2021-03-01 10:15 squashfs-root/hello-world
dr-xr-xr-x user/user                 3 2021-03-01 10:15 squashfs-root/lib
dr-xr-xr-x user/user                 3 2021-03-01 10:15 squashfs-root/lib64
dr--r--r-- user/user                 3 2021-03-01 10:15 squashfs-root/proc
dr-xr-xr-x user/user                 3 2021-03-01 10:15 squashfs-root/system
```

## Inspecting an NPK with the `--short` parameter

To facilitate the inspection of many containers as part of scripts, the
`inspect` command features the `--short` parameter.  It condenses the inspection
output into a single line with the following information:

- Container name
- Container version
- NPK format version
- Whether or not this is a [resource container](npk_format_reference.md#resource-containers)

Inspecting the `hello-world` example container with the `--short` flag gives the
following output:

```markdown
$ sextant inspect --short target/northstar/repository/hello-world-0.0.1.npk 
`name: hello-world, version: 0.0.1, NPK version: 0.0.2, resource container: no`
```
