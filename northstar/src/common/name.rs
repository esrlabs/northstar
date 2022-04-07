use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt::{Display, Formatter},
    ops::Deref,
};
use thiserror::Error;

/// Name of a container
#[derive(
    Clone, Eq, PartialOrd, Ord, PartialEq, Debug, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(try_from = "String")]
pub struct Name(String);

/// Invalid character in name
#[derive(Error, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[error("invalid character(s) in name")]
pub struct InvalidNameChar(usize);

impl InvalidNameChar {
    /// Position of a null byte
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
