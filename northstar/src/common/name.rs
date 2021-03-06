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

use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt::{Display, Formatter},
    ops::Deref,
};
use thiserror::Error;

#[derive(Clone, Eq, PartialOrd, PartialEq, Debug, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Name(String);

#[derive(Error, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[error("Invalid character(s) in name")]
pub struct InvalidNameChar(usize);

impl InvalidNameChar {
    pub fn nul_position(&self) -> usize {
        self.0
    }
}

impl Display for Name {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl Deref for Name {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<String> for Name {
    type Error = InvalidNameChar;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Some(pos) =
            value.find(|c: char| !matches!(c, '0'..='9' | 'A'..='Z' | 'a'..='z' | '.' | '_' | '-'))
        {
            Err(InvalidNameChar(pos))
        } else {
            Ok(Name(value))
        }
    }
}

impl TryFrom<&str> for Name {
    type Error = InvalidNameChar;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl Name {
    /// &str representation of a Name
    pub fn to_str(&self) -> &str {
        self.0.as_str()
    }
}
