/// Northstar integration test
#[macro_export]
macro_rules! test {
    ($name:ident, $e:expr) => {
        rusty_fork::rusty_fork_test! {
            #![rusty_fork(timeout_ms = 300000)]
            #[test]
            fn $name() {
                crate::logger::init();
                log::set_max_level(log::LevelFilter::Debug);

                // Enter a mount namespace. This needs to be done before spawning
                // the tokio threadpool.
                nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS).unwrap();

                // Set the mount propagation to private on root. This ensures that *all*
                // mounts get cleaned up upon process termination. The approach to bind
                // mount the run_dir only (this is where the mounts from northstar happen)
                // doesn't work for the tests since the run_dir is a tempdir which is a
                // random dir on every run. Checking at the beginning of the tests if
                // run_dir is bind mounted - a leftover from a previous crash - obviously
                // doesn't work. Technically, it is only necessary set the propagation of
                // the parent mount of the run_dir, but this not easy to find and the change
                // of mount propagation on root is fine for the tests which are development
                // only.
                nix::mount::mount(
                    Some("/"),
                    "/",
                    Option::<&str>::None,
                    nix::mount::MsFlags::MS_PRIVATE | nix::mount::MsFlags::MS_REC,
                    Option::<&'static [u8]>::None,
                )
                .expect(
                    "Failed to set mount propagation to private on
                root",
                );
                let runtime = northstar_tests::runtime::Runtime::new().expect("Failed to start runtime");

                match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .thread_name(stringify!($name))
                    .build()
                    .expect("Failed to start runtime")
                    .block_on(async {
                        let runtime = runtime.start().await?;
                        $e
                        northstar_tests::runtime::client().shutdown().await?;
                        drop(runtime);
                        tokio::fs::remove_file(northstar_tests::runtime::console().path()).await?;
                        Ok(())
                    }) {
                        Ok(_) => std::process::exit(0),
                        anyhow::Result::<()>::Err(e) => panic!("{}", e),
                    }
            }
        }
    };
}
