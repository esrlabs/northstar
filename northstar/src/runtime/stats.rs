use std::collections::HashMap;

/// See the `serde_json::value` module documentation for usage examples.
pub type Value = serde_json::Value;

/// Convert a `T` into `Value` which is an enum that can represent
/// any valid JSON data.
pub(super) use serde_json::to_value;

/// Set of statistics
pub type ContainerStats = HashMap<String, Value>;
