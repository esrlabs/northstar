# Seccomp helper utility

Utility to generate seccomp profiles for Northstar containers.

## Create a seccomp manifest entry

To enable seccomp for container, a suitable `seccomp` entry is required in the
container's manifest file.  Using `northstar-seccomp`, such an entry can be created
with the following steps:

1. Run the container with strace to generate a syscall log.
2. Run `northstar-seccomp` on the syscall log to generate a seccomp manifest entry.
3. Optional: Restrict the arguments of syscalls to specific values.
4. Add the seccomp manifest entry to the container's manifest.

## Example Usage

An example strace log obtained by running a northstar container with strace
could look as follows:

```shell
$ cat ./target/northstar/logs/strace-259876-seccomp.strace
[pid 193911] brk(NULL)                  = 0x5572b5c8b000
[pid 193911] arch_prctl(0x3001 /* ARCH_??? */, 0x7fff814606c0) = -1 EINVAL (Invalid argument)
[pid 193911] access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
[pid 193911] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid 193911] openat(AT_FDCWD, "/lib64/glibc-hwcaps/x86-64-v3/libgcc_s.so.1", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[...]
[pid 193911] delete_module(NULL, -1)                   = 0
[...]
[pid 193911] write(1, "Hello from the seccomp example version 0.0.1!\n", 46) = 46
[...]
```

Running `northstar-seccomp` on the file gives the following output:

```shell
$ northstar-seccomp ./target/northstar/logs/strace-259876-seccomp.strace
profile: default
seccomp:
  allow:
    delete_module: any
```

Since all syscalls from the trace file except `delete_module` are part of the
default profile, `northstar-seccomp` did not explicitly add them to the `allow:`
part of the entry.

If we do not want to use the default profile, we can add the
`--no-default-profile` command line switch to disable it. `northstar-seccomp`
will then list all used syscalls explicitly:

```shell
$ northstar-seccomp --no-default-profile ./target/northstar/logs/strace-259876-seccomp.strace
seccomp:
  allow:
    brk: any
    arch_prctl: any
    access: any
    openat: any
[...]
    delete_module: any
[...]
    write: any
[...]
```

If we want to restrict the `write` syscall to write to `stdout` only, we need to
modify its `seccomp` entry.  The target file descriptor is passed in the first
argument of the `write` syscall and according to POSIX, `stdout` always has a
file descriptor value of `1`.  We can therefore modify the `seccomp` entry as
follows:

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

Note that if there are multiple rules for a single syscall, then all rules are
evaluated and the syscall only fails if none of the rules allow it.

In particular, consider the following seccomp entry:

```shell
seccomp:
  profile: default
  allow:
    write: 
      args:
        args:
        index: 0
        values: [
            1,
        ]
```

Since the default profile already allows the `write` syscall without imposing
any restrictions on the arguments, the entry for `write` in the `allow:` part of
the entry is redundant.  It is therefore equivalent to the following entry:

```shell
seccomp:
  profile: default
```
