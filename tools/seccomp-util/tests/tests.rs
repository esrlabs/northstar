use anyhow::Result;

#[test]
fn parse_strace_log() -> Result<()> {
    use assert_cmd::Command;

    const EXPECTED: &str = "---
profile: default
allow:
  delete_module: any

";
    let stdout = String::from_utf8(
        Command::cargo_bin("seccomp-util")?
            .arg("./res/test_strace_data.txt")
            .output()?
            .stdout,
    )?;
    assert_eq!(stdout, EXPECTED);
    Ok(())
}

#[test]
fn parse_strace_log_without_profile() -> Result<()> {
    use assert_cmd::Command;

    const EXPECTED: &str = "---
allow:
  brk: any
  arch_prctl: any
  access: any
  delete_module: any
  openat: any
  newfstatat: any
  read: any
  mmap: any
  mprotect: any
  close: any
  pread64: any
  set_tid_address: any
  set_robust_list: any
  rt_sigaction: any
  rt_sigprocmask: any
  prlimit64: any
  poll: any
  sigaltstack: any
  sched_getaffinity: any
  write: any
  clock_nanosleep: any
  munmap: any
  exit_group: any

";
    let stdout = String::from_utf8(
        Command::cargo_bin("seccomp-util")?
            .arg("./res/test_strace_data.txt")
            .arg("--no-default-profile")
            .output()?
            .stdout,
    )?;
    let lines = stdout.lines().collect::<Vec<&str>>();
    let expected_lines = EXPECTED.lines().collect::<Vec<&str>>();
    assert_eq!(lines.len(), expected_lines.len());
    assert_eq!(lines[0], "---");
    assert_eq!(lines[1], "allow:");
    for line in lines {
        assert!(expected_lines.contains(&line));
    }
    Ok(())
}
