// Copyright (c) 2019 - 2021 ESRLabs
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

#![deny(clippy::all)]

pub mod common;

#[cfg(feature = "api")]
/// Northstar remote API. Control start and stop of applications and
/// receive updates about container states.
pub mod api;

#[cfg(feature = "npk")]
/// NPK format support.
pub mod npk;

#[cfg(feature = "runtime")]
/// The Northstar runtime core.
pub mod runtime;

#[cfg(feature = "seccomp")]
/// Support for seccomp syscall filtering.
pub mod seccomp;

/// Northstar internal utilities
#[cfg(feature = "runtime")]
mod util;
