# Seccomp helper utility

Utility to generate seccomp profiles for Northstar containers.

## Create a seccomp manifest entry

To enable seccomp for container, a suitable `seccomp` entry is required in the container's manifest 
file.
Using `seccomp-util`, such an entry can be created with the following steps:

1. Run the container with strace to generate a syscall log.
2. Run `seccomp-util` on the syscall log to generate a seccomp manifest entry. 
3. Optional: Restrict the arguments of syscalls to specific values.
4. Add the seccomp manifest entry to the container's manifest.

## Example Usage

An example strace log obtained by running a northstar container with strace could look as follows: 

```shell
$ cat ./target/northstar/logs/strace-259876-seccomp.strace
[pid 193911] brk(NULL)                  = 0x5572b5c8b000
[pid 193911] arch_prctl(0x3001 /* ARCH_??? */, 0x7fff814606c0) = -1 EINVAL (Invalid argument)
[pid 193911] access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
[pid 193911] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid 193911] openat(AT_FDCWD, "/lib64/glibc-hwcaps/x86-64-v3/libgcc_s.so.1", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[...]
[pid 193911] write(1, "Hello from the seccomp example version 0.0.1!\n", 46) = 46
[...]
```

Running `seccomp-util` on the file gives the following output:

```shell
$ seccomp-util ./target/northstar/logs/strace-259876-seccomp.strace
seccomp:
  allow:
    brk: any
    arch_prctl: any
    access: any
    openat: any
[...]
    write: any
[...]
```

If we want to restrict the `write` syscall to write to `stdout` only, we need to modify its 
`seccomp` entry.
The target file descriptor is passed in the first argument of the `write` syscall 
and according to POSIX, `stdout` always has a file descriptor value of `1`.
We can therefore modify the `seccomp` entry as follows:

```shell
seccomp:
  allow:
    brk: any
    arch_prctl: any
    access: any
    openat: any
[...]
    write: 
      args:
        args:
        index: 0
        values: [
            1,
        ]
[...]
```

The modified seccomp entry can now be added to the container's `manifest.yaml` file.