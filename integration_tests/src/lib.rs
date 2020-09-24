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

pub mod capture_reader;
pub mod north_runtime;
pub mod process_assert;
pub mod util;

#[cfg(test)]
mod test {
    use crate::{north_runtime::NorthRuntime, util::Timeout};
    use anyhow::{Context, Result};
    use async_std::{fs, path::Path};

    fn init_logger() {
        env_logger::builder().is_test(true).try_init().ok();
    }

    #[ignore]
    #[async_std::test]
    async fn check_hello() -> Result<()> {
        init_logger();
        let mut north = NorthRuntime::launch().await?;

        let hello = north.start("hello").await?;

        // Here goes some kind of health check for the spawned process
        assert!(hello.is_running().await?);

        north.stop("hello").await?;
        north.shutdown().await
    }

    #[ignore]
    #[async_std::test]
    async fn check_cpueater() -> Result<()> {
        init_logger();
        let mut north = NorthRuntime::launch().await?;

        let cpueater = north.start("cpueater").await?;

        // Here goes some kind of health check for the spawned process
        assert_eq!(cpueater.get_cpu_shares().await?, 100);
        assert!(cpueater.is_running().or_timeout_in_secs(1).await??);

        // Stop the cpueater process
        north.stop("cpueater").await?;
        north.shutdown().await
    }

    #[ignore]
    #[async_std::test]
    async fn check_memeater() -> Result<()> {
        init_logger();

        let mut north = NorthRuntime::launch().await?;

        let memeater = north.start("memeater").await?;

        // Here goes some kind of health check for the spawned process
        assert!(memeater.is_running().or_timeout_in_secs(1).await??);

        // TODO why is this not equal?
        // println!("{} != {}", memeater.get_limit_in_bytes().await?, 100000000);

        // stop the memeater process
        north.stop("memeater").await?;
        north.shutdown().await
    }

    #[ignore]
    #[async_std::test]
    async fn check_datarw_mount() -> Result<()> {
        init_logger();

        let mut north = NorthRuntime::launch().await?;

        let data_dir = Path::new("../target/north/data/test_container-000/")
            .canonicalize()
            .await?;
        let input_file = data_dir.join("input.txt");

        // Write the input to the test_container
        fs::write(&input_file, b"echo hello there!").await?;

        // Start the test_container process
        north.start("test_container-000").await.map(drop)?;

        north
            .expect_output("hello there!")
            .or_timeout_in_secs(5)
            .await?
            .context("Failed to find expected test_container output")?;

        north.try_stop("test_container-000").await?;

        // Remove the temporary data directory
        fs::remove_file(input_file).await?;

        north.shutdown().await
    }

    #[ignore]
    #[async_std::test]
    async fn check_crashing_container() -> Result<()> {
        init_logger();

        let data_dir = Path::new("../target/north/data/").canonicalize().await?;

        let mut north = NorthRuntime::launch().await?;

        for i in 0..5 {
            fs::write(
                data_dir.join(format!("test_container-0{:02}/input.txt", i)),
                b"crash",
            )
            .await?;

            // Start the test_container process
            north
                .start(&format!("test_container-0{:02}", i))
                .await
                .map(drop)?;
        }

        // Try to stop the containers before issuing the shutdown
        for i in 0..5 {
            north.try_stop(&format!("test_container-0{:02}", i)).await?;
        }

        north.shutdown().await
    }
}
