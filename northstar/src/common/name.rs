use schemars::{
    gen::SchemaGenerator,
    schema::{InstanceType, SchemaObject, StringValidation},
    JsonSchema,
};
use serde::{de::Visitor, Deserialize, Serialize, Serializer};
use std::{
    convert::{TryFrom, TryInto},
    fmt::{self, Formatter},
};
use thiserror::Error;

use super::non_nul_string::{InvalidNulChar, NonNulString};

/// Maximum length allowed for a container name
const MAX_LENGTH: usize = 1024;

/// Name of a container. A Container name cannot be empty and cannot contain a null bytes
/// because it is used to generated file names etc.. There's a set of valid characters
/// allowed in container names: '0'..='9' | 'A'..='Z' | 'a'..='z' | '.' | '_' | '-'.
/// The maximum length allowed for a container name is 1024 characters.
#[derive(Clone, Eq, PartialOrd, Ord, PartialEq, Hash)]
pub struct Name(NonNulString);

/// Invalid character in name
#[derive(Error, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[error("invalid character(s) in name")]
pub enum NameError {
    /// Name is empty
    #[error("container name cannot be empty")]
    Empty,
    #[error("container name cannot longer than 1024 characters")]
    /// Name exceeds maximum length
    Length,
    #[error("container name contains invalid character(s): {0}")]
    /// Name contains invalid character(s)
    InvalidChar(char),
    /// Name contains null byte
    #[error("container name cannot contain a nul byte at position {0}")]
    ContainsNul(usize),
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for Name {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<String> for Name {
    type Error = NameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.len() {
            0 => return Err(NameError::Empty),
            n if n > MAX_LENGTH => return Err(NameError::Length),
            _ => (),
        }

        let value: NonNulString = value
            .try_into()
            .map_err(|e: InvalidNulChar| NameError::ContainsNul(e.pos()))?;

        if let Some(c) = value
            .chars()
            .find(|c| !matches!(c, '0'..='9' | 'A'..='Z' | 'a'..='z' | '.' | '_' | '-'))
        {
            return Err(NameError::InvalidChar(c));
        }

        Ok(Name(value))
    }
}

impl TryFrom<&str> for Name {
    type Error = NameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl From<Name> for NonNulString {
    fn from(value: Name) -> Self {
        value.0
    }
}

impl Serialize for Name {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NameVisitor;

        impl<'de> Visitor<'de> for NameVisitor {
            type Value = Name;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "valid non empty string without nul bytes: ('0'..='9' | 'A'..='Z' | 'a'..='z' | '.' | '_' | '-')+",
                )
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                v.try_into().map_err(|_| E::custom("invalid name"))
            }
        }

        deserializer.deserialize_str(NameVisitor)
    }
}

impl JsonSchema for Name {
    fn schema_name() -> String {
        "Name".to_string()
    }

    fn json_schema(_: &mut SchemaGenerator) -> schemars::schema::Schema {
        SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            string: Some(Box::new(StringValidation {
                min_length: Some(1),
                max_length: Some(MAX_LENGTH as u32),
                pattern: Some("([0-9]|[A-Z]|[a-z]|\\.|_|-)+".into()),
            })),
            ..Default::default()
        }
        .into()
    }
}

#[test]
fn try_empty() {
    assert!(matches!(Name::try_from(""), Err(NameError::Empty)));
}

#[test]
fn try_too_long() {
    assert!(matches!(Name::try_from("a".repeat(1024)), Ok(_)));
    assert!(matches!(
        Name::try_from("a".repeat(2000)),
        Err(NameError::Length)
    ));
}

#[test]
fn try_invalid_char() {
    assert!(matches!(
        Name::try_from("a%"),
        Err(NameError::InvalidChar('%'))
    ));
    assert!(matches!(
        Name::try_from("^foo"),
        Err(NameError::InvalidChar('^'))
    ));
    assert!(matches!(
        Name::try_from("test*"),
        Err(NameError::InvalidChar('*'))
    ));
}

#[test]
fn try_from_nul_bytes() {
    assert!(matches!(
        Name::try_from("\0"),
        Err(NameError::ContainsNul(0))
    ));
    assert!(matches!(
        Name::try_from("a\0b"),
        Err(NameError::ContainsNul(1))
    ));
}

#[test]
fn serialize() {
    assert!(matches!(
        serde_json::to_string(&Name::try_from("a").unwrap()),
        Ok(s) if s == "\"a\""
    ));
}

#[test]
fn deserialize() {
    assert!(matches!(
        serde_json::from_str::<Name>("\"a\""),
        Ok(n) if n == Name::try_from("a").unwrap()
    ));
    assert!(matches!(serde_json::from_str::<Name>("\"a\0\""), Err(_)));
}

#[test]
fn schema() {
    schemars::schema_for!(Name);
}
