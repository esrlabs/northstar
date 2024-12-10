use anyhow::{bail, Result};
use serde::{de::Visitor, Deserialize, Serialize, Serializer};
use std::{
    convert::{TryFrom, TryInto},
    fmt::{self, Formatter},
};
use thiserror::Error;

use super::non_nul_string::NonNulString;

/// Maximum length allowed for a container name
const MAX_LENGTH: usize = 1024;

/// Name of a container. A Container name cannot be empty and cannot contain a null bytes
/// because it is used to generated file names etc.. There's a set of valid characters
/// allowed in container names: '0'..='9' | 'A'..='Z' | 'a'..='z' | '.' | '_' | '-'.
/// The maximum length allowed for a container name is 1024 characters.
#[derive(Clone, Eq, PartialOrd, Ord, PartialEq, Hash)]
pub struct Name(NonNulString);

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

/// Name parse error
#[derive(Error, Debug)]
#[error(transparent)]
pub struct InvalidNameError(#[from] anyhow::Error);

/// Validate the input string as a container name
fn validate(name: String) -> Result<Name> {
    let name = NonNulString::try_from(name)?;

    if name.len() == 0 {
        bail!("container name is empty");
    } else if name.len() > MAX_LENGTH {
        bail!("container name is longer than 1024 characters");
    }

    if let Some(c) = name
        .chars()
        .find(|c| !matches!(c, '0'..='9' | 'A'..='Z' | 'a'..='z' | '.' | '_' | '-'))
    {
        bail!("invalid character: {}", c);
    }

    Ok(Name(name))
}

impl TryFrom<String> for Name {
    type Error = InvalidNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(validate(value)?)
    }
}

impl TryFrom<&str> for Name {
    type Error = InvalidNameError;

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

        impl Visitor<'_> for NameVisitor {
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

#[test]
fn try_empty() {
    assert!(Name::try_from("").is_err());
}

#[test]
fn try_too_long() {
    assert!(Name::try_from("a".repeat(1024)).is_ok());
    assert!(Name::try_from("a".repeat(2000)).is_err());
}

#[test]
fn try_invalid_char() {
    assert!(Name::try_from("a%").is_err());
    assert!(Name::try_from("^foo").is_err());
    assert!(Name::try_from("test*").is_err());
}

#[test]
fn try_from_nul_bytes() {
    assert!(Name::try_from("\0").is_err());
    assert!(Name::try_from("a\0b").is_err());
}

#[test]
#[allow(clippy::unwrap_used)]
fn serialize() {
    assert!(matches!(
        serde_json::to_string(&Name::try_from("a").unwrap()),
        Ok(s) if s == "\"a\""
    ));
}

#[test]
#[allow(clippy::unwrap_used)]
fn deserialize() {
    assert!(matches!(
        serde_json::from_str::<Name>("\"a\""),
        Ok(n) if n == Name::try_from("a").unwrap()
    ));
    assert!(serde_json::from_str::<Name>("\"a\0\"").is_err());
}

#[test]
#[should_panic]
#[allow(clippy::unwrap_used)]
fn deserialize_name_contains_slash() {
    serde_json::from_str::<Name>("test/../test").unwrap();
}
