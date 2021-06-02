# Steps performed by minijail to load the seccomp example container

## 1. Create and install seccomp filters

### Description

<https://lwn.net/Articles/494252/>

### Rust Crate

<https://crates.io/crates/seccomp>

### Manual (using libseccomp)

- <https://www.man7.org/linux/man-pages/man3/seccomp_init.3.html>
- <https://www.man7.org/linux/man-pages/man3/seccomp_rule_add.3.html>
- <https://www.man7.org/linux/man-pages/man3/seccomp_load.3.html>
- <https://www.man7.org/linux/man-pages/man3/seccomp_release.3.html>

## 2. Call `minijail_run_internal`

### Rust alternative APIs

- <https://doc.rust-lang.org/std/process/index.html>
- <https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html>
- <https://docs.rs/nix/0.20.0/nix/unistd/index.html>
- <https://docs.rs/unshare/0.6.0/unshare/>

### `minijail_run_internal` Steps

1. Create pipes for stdin/stdout/stderr as requested by caller.

2. Configure the child's runtime

    ```c
    /*
    * If the parent process needs to configure the child's runtime
    * environment after forking, create a pipe(2) to block the child until
    * configuration is done.
    */
    if (j->flags.forward_signals || j->flags.pid_file || j->flags.cgroups || j->rlimit_count || j->flags.userns) {...}
    ```

    Probably not needed for northstar

3. clone/fork

    - Use sys_clone() if and only if we're creating a pid namespace.  
      We eventaully want to use PID namespaces but have to solve the multithreading issues minijail is facing

    - Otherwise: Fork  

4. Duplicate all parent fds in child and close all fds that are not also childs fds

    ```c
    redirect_fds(j)
    /*
     * After all fds have been duped, we are now free to close all parent
     * fds that are *not* child fds.
     */
    ```

5. Set up stdin/stdout/stderr file descriptors of the child

    setup_child_std_fds(j, state_out);

6. Call minijail_enter
    - if (vfs=-1)  
      unshare(CLONE_NEWNS)
  
    - if (chroot=-1 )  
      chroot(j->chrootdir)  
      chdir("/")
  
    - if (remount_proc_ro=-1)

      ```c
      /*
      * Right now, we're holding a reference to our parent's old mount of
      * /proc in our namespace, which means using MS_REMOUNT here would
      * mutate our parent's mount as well, even though we're in a VFS
      * namespace (!). Instead, remove their mount from our namespace lazily
      * (MNT_DETACH) and make our own.
      */
      umount2(kProcPath, MNT_DETACH)
      mount("proc", kProcPath, "proc", kSafeFlags | MS_RDONLY, "")
      ```
  
    - if (no_new_privs=-1)

      ```c
      /*
       * If we're setting no_new_privs, we can drop privileges
       * before setting seccomp filter. This way filter policies
       * don't need to allow privilege-dropping syscalls.
       */
       drop_ugid(j);
       drop_caps(j, last_valid_cap);
       set_seccomp_filter(j);
      ```

    - if (seccomp_filter=-1)  
      `prctl(PR_SET_SECCOMP, 1)`  
      Could be handled by seccomp_load() instead.

7. If PID namespaces are used: fork child process again and let child catch SIGTERM from grandchild

    ```c
    /*
     * pid namespace: this process will become init inside the new
     * namespace. We don't want all programs we might exec to have
     * to know how to be init. Normally (do_init == 1) we fork off
     * a child to actually run the program. If |do_init == 0|, we
     * let the program keep pid 1 and be init.
     *
     * If we're multithreaded, we'll probably deadlock here. See
     * WARNING above.
     */
    ```

8. Execute

    `execve(config->filename, config->argv, child_env);`

## seccomp container effective jail flags

- uid=-1
- gid=-1
- vfs=-1
- remount_proc_ro=-1
- no_new_privs=-1
- seccomp_filter=-1
- seccomp_filter_logging=-1
- chroot=-1
- mount_dev=-1
- do_init=-1
- close_open_fds=-1

## seccomp container all jail flags

- uid=-1
- gid=-1
- inherit_suppl_gids=0
- set_suppl_gids=0
- keep_suppl_gids=0
- use_caps=0
- capbset_drop=0
- set_ambient_caps=0
- vfs=-1
- enter_vfs=0
- pids=0
- ipc=0
- uts=0
- net=0
- enter_net=0
- ns_cgroups=0
- userns=0
- disable_setgroups=0
- seccomp=0
- remount_proc_ro=-1
- no_new_privs=-1
- seccomp_filter=-1
- seccomp_filter_tsync=0
- seccomp_filter_logging=-1
- chroot=-1
- pivot_root=0
- mount_dev=-1
- mount_tmp=0
- do_init=-1
- run_as_init=0
- pid_file=0
- cgroups=0
- alt_syscall=0
- reset_signal_mask=0
- reset_signal_handlers=0
- close_open_fds=-1
- new_session_keyring=0
- forward_signals=0
- setsid=0
