// Copyright (c) 2021 ESRLabs
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

use std::collections::HashMap;

/// See the `serde_json::value` module documentation for usage examples.
pub type Value = serde_json::Value;

/// Convert a `T` into `Value` which is an enum that can represent
/// any valid JSON data.
pub(super) use serde_json::to_value;

/// Set of statistics
pub type ContainerStats = HashMap<String, Value>;
