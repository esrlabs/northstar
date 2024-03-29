use nix::{
    libc,
    unistd::{self, Gid},
};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

use crate::dump;

pub fn run() {
    println!("getpid: {}", unistd::getpid());
    println!("getppid: {}", unistd::getppid());
    println!("getuid: {}", unistd::getuid());
    println!("getgid: {}", unistd::getgid());
    println!("getsid: {}", unistd::getsid(None).unwrap());
    println!("getpgid: {}", unistd::getpgid(None).unwrap());
    println!(
        "getgroups: {:?}",
        unistd::getgroups()
            .expect("getgroups")
            .iter()
            .cloned()
            .map(Gid::as_raw)
            .collect::<Vec<_>>()
    );
    println!(
        "pwd: {}",
        env::current_dir().expect("current_dir").display()
    );
    println!(
        "exe: {}",
        env::current_exe().expect("current_exe").display()
    );
    println!("sched_getscheduler: {}", unsafe {
        libc::sched_getscheduler(0)
    });
    println!("sched_priority: {}", unsafe {
        #[cfg(not(target_env = "musl"))]
        let mut params = libc::sched_param { sched_priority: 0 };
        #[cfg(target_env = "musl")]
        let mut params = libc::sched_param {
            sched_priority: 0,
            sched_ss_low_priority: 0,
            sched_ss_repl_period: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            sched_ss_init_budget: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            sched_ss_max_repl: 0,
        };
        assert_eq!(
            libc::sched_getparam(0, &mut params as *mut libc::sched_param),
            0
        );
        params.sched_priority
    });
    #[cfg(any(target_env = "musl", target_os = "android"))]
    println!("getpriority: {}", unsafe {
        libc::getpriority(0, libc::PRIO_PROCESS.try_into().unwrap())
    });
    #[cfg(all(not(target_env = "musl"), not(target_os = "android")))]
    println!("getpriority: {}", unsafe {
        libc::getpriority(0, libc::PRIO_PROCESS)
    });

    for set in &[
        caps::CapSet::Ambient,
        caps::CapSet::Bounding,
        caps::CapSet::Effective,
        caps::CapSet::Inheritable,
        caps::CapSet::Permitted,
    ] {
        println!(
            "caps {}: {:?}",
            format!("{set:?}").as_str().to_lowercase(),
            caps::read(None, *set).expect("failed to read caps")
        );
    }

    println!("/proc/self/fd:");
    fs::read_dir("/proc/self/fd")
        .expect("read_dir /proc/self/fd")
        .map(|e| e.unwrap().path())
        .map(|p| (p.clone(), fs::read_link(p).expect("readlink entry")))
        .filter(|(_, l)| l != &PathBuf::from(format!("/proc/{}/fd", std::process::id())))
        .for_each(|(p, l)| {
            println!("    {}: {}", p.display(), l.display());
        });
    // Substract the ReadDir fd
    println!(
        "    total: {}",
        fs::read_dir("/proc/self/fd").unwrap().count() - 1
    );

    dump(Path::new("/proc/self/mounts"));
    dump(Path::new("/proc/self/limits"));
}
