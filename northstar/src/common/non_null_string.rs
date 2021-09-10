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

use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt::{Display, Formatter},
    ops::Deref,
};
use thiserror::Error;

#[derive(Clone, Eq, PartialOrd, PartialEq, Debug, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct NonNullString(String);

#[derive(Error, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[error("Invalid null byte in string")]
pub struct InvalidNullChar(usize);

impl Display for NonNullString {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl AsRef<[u8]> for NonNullString {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Deref for NonNullString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<String> for NonNullString {
    type Error = InvalidNullChar;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Some(pos) = value.find('\0') {
            Err(InvalidNullChar(pos))
        } else {
            Ok(NonNullString(value))
        }
    }
}

impl TryFrom<&str> for NonNullString {
    type Error = InvalidNullChar;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl NonNullString {
    pub fn to_str(&self) -> &str {
        self.0.as_str()
    }
}

impl InvalidNullChar {
    pub fn nul_position(&self) -> usize {
        self.0
    }
}
