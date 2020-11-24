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

//! Set of assertions wrapped to OS processes

use color_eyre::eyre::{eyre, Result, WrapErr};
use regex::Regex;
use std::path::PathBuf;
use tokio::fs;

#[derive(Debug, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Sleeping,
    Waiting,
    Zombie,
}

/// Wrapper around a process's PID intended for assertions on the process configuration
pub struct ProcessAssert {
    pid: u64,
}

impl ProcessAssert {
    /// Wraps `pid` with a ProcessAssert
    pub fn new(pid: u64) -> ProcessAssert {
        ProcessAssert { pid }
    }

    /// Checks if the process is currently running
    pub async fn is_running(&self) -> Result<bool> {
        use ProcessState::*;
        Ok(matches!(
            self.get_state().await?,
            Some(Running) | Some(Waiting) | Some(Sleeping)
        ))
    }

    /// If the cpu cgroup is configured, returns the number of cpu shares
    pub async fn get_cpu_shares(&self) -> Result<u64> {
        let mut cgroup_path = self
            .get_cgroup_path("cpu")
            .await
            .wrap_err("Failed to find the cgroup path")?;
        cgroup_path.push("cpu.shares");

        fs::read_to_string(cgroup_path.as_path())
            .await
            .map(|s| s.trim().to_owned())?
            .parse()
            .wrap_err("Failed to parse CPU shares")
    }

    /// Return the limit in bytes set in the process's memory cgroup
    pub async fn get_limit_in_bytes(&self) -> Result<u64> {
        let cgroup_path = self
            .get_cgroup_path("memory")
            .await
            .wrap_err("Failed to find the cgroup path")?
            .join("memory.limit_in_bytes");
        fs::read_to_string(&cgroup_path)
            .await
            .map(|s| s.trim().to_owned())?
            .parse()
            .wrap_err("Failed to parse memory limit")
    }

    /// Checks the process's state
    async fn get_state(&self) -> Result<Option<ProcessState>> {
        let stat = fs::read_to_string(format!("/proc/{}/stat", self.pid))
            .await
            .wrap_err("Failed to read proc stat")?;

        use ProcessState::*;
        match stat.split_whitespace().nth(2) {
            Some("R") => Ok(Some(Running)),
            Some("S") => Ok(Some(Sleeping)),
            Some("D") => Ok(Some(Waiting)),
            Some("Z") => Ok(Some(Zombie)),
            _ => Ok(None),
        }
    }

    /// Get the path to the cgroup directory from the process's /proc cgroup configuration
    async fn get_cgroup_path(&self, cgroup_name: &str) -> Result<PathBuf> {
        let cgroups = fs::read_to_string(format!("/proc/{}/cgroup", self.pid)).await?;
        let re = Regex::new(&format!(
            r"\d+:(\w+,)*{}(,\w+)*:(?P<path>[\w.\-/]+)",
            cgroup_name
        ))
        .expect("Invalid regular expression");
        if let Some(path) = cgroups
            .lines()
            .filter_map(|line| re.captures(&line))
            .filter_map(|cap| cap.name("path").map(|p| p.as_str()))
            .next()
        {
            Ok(format!("/sys/fs/cgroup/{}{}", cgroup_name, path).into())
        } else {
            Err(eyre!("Failed to find cgroup configuration"))
        }
    }
}
