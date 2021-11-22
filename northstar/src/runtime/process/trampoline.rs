use super::{init::Init, Checkpoint};
use crate::runtime::ipc::channel::Channel;
use nix::{sched, unistd};
use std::process::exit;

pub(super) fn trampoline(init: Init, mut child_channel: Channel, checkpoint_init: Checkpoint) -> ! {
    // Create pid namespace
    sched::unshare(sched::CloneFlags::CLONE_NEWPID).expect("Failed to create pid namespace");

    // Fork the init process
    match unsafe { unistd::fork() }.expect("Failed to fork init") {
        unistd::ForkResult::Parent { child } => {
            // Send the pid of init to the runtime and exit
            let pid = child.as_raw() as i32;
            child_channel.send(&pid).expect("Failed to send init pid");
            exit(0);
        }
        unistd::ForkResult::Child => {
            // Wait for the runtime to signal that init may start.
            let condition_notify = checkpoint_init.wait();

            // Dive into init and never return
            init.run(condition_notify, child_channel);
        }
    }
}
