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

//! Extends Future with timeout methods

use anyhow::Result;
use async_std::future::{timeout, Future};
use async_trait::async_trait;
use std::time::Duration;

/// Extends Future with timeout methods
#[async_trait]
pub trait Timeout: Sized + Future {
    /// Times out if the tasks takes longer than `duration`
    async fn or_timeout(self, duration: Duration) -> Result<Self::Output> {
        timeout(duration, self).await.map_err(anyhow::Error::new)
    }

    /// Times out if the tasks takes longer than the `secs`
    async fn or_timeout_in_secs(self, secs: u64) -> Result<Self::Output> {
        self.or_timeout(Duration::from_secs(secs)).await
    }
}

#[async_trait]
impl<T: Sized + Future> Timeout for T {}
