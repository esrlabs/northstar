// Copyright (c) 2019 - 2020 ESRLabs
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

use crate::logger::LogParser;
use colored::control::ShouldColorize;
use log::LevelFilter;
use std::sync::Once;

static INIT: Once = Once::new();
static LOGGER: LogParser = LogParser;

pub fn init() {
    INIT.call_once(|| {
        color_eyre::install().unwrap();
        ShouldColorize::from_env();
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(LevelFilter::Debug);

        // TODO make the test independent of the workspace structure
        // set the CWD to the root
        std::env::set_current_dir("..").unwrap();

        // Set the mount propagation of unshare_root to MS_PRIVATE
        nix::mount::mount(
            Option::<&'static [u8]>::None,
            "/",
            Some("ext4"),
            nix::mount::MsFlags::MS_PRIVATE,
            Option::<&'static [u8]>::None,
        )
        .unwrap();

        // Enter a mount namespace. This needs to be done before spawning
        // the tokio threadpool.
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS).unwrap();
    })
}

#[macro_export]
macro_rules! test {
    ($name:ident, $e:expr) => {
        rusty_fork::rusty_fork_test! {
            #![rusty_fork(timeout_ms = 300000)]
            #[test]
            fn $name() {
                ::northstar_tests::macros::init();
                logger::reset();
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_name(stringify!($name))
                    .build()
                    .expect("Failed to start runtime")
                    .block_on(async { $e })
                    .expect("Test failed");
            }
        }
    };
}
