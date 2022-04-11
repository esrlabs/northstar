use schemars::{
    gen::SchemaGenerator,
    schema::{InstanceType, SchemaObject, StringValidation},
    JsonSchema,
};
use serde::{Deserialize, Serialize, Serializer};
use std::{
    convert::{TryFrom, TryInto},
    ffi::CString,
    fmt::{self, Formatter},
    ops::Deref,
    path::Path,
};
use thiserror::Error;

/// String that does not contain null bytes
#[derive(Clone, Eq, PartialOrd, Ord, PartialEq, Hash)]
pub struct NonNulString(String);

impl NonNulString {
    /// Returns the underlying string
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Null byte error
#[derive(Error, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[error("invalid null byte in string")]
pub struct InvalidNulChar(usize);

impl InvalidNulChar {
    /// Returns the index of the null byte
    pub fn pos(&self) -> usize {
        self.0
    }
}

impl fmt::Display for NonNulString {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for NonNulString {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "\"{}\"", self.0)
    }
}

impl AsRef<[u8]> for NonNulString {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl AsRef<str> for NonNulString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<Path> for NonNulString {
    fn as_ref(&self) -> &Path {
        Path::new(self.0.as_str())
    }
}

impl Deref for NonNulString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<NonNulString> for CString {
    fn from(s: NonNulString) -> Self {
        unsafe { CString::from_vec_unchecked(s.0.into()) }
    }
}

impl TryFrom<String> for NonNulString {
    type Error = InvalidNulChar;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Some(pos) = memchr::memchr(b'\0', value.as_bytes()) {
            Err(InvalidNulChar(pos))
        } else {
            Ok(NonNulString(value))
        }
    }
}

impl TryFrom<&str> for NonNulString {
    type Error = InvalidNulChar;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl Serialize for NonNulString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for NonNulString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = NonNulString;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("string without nul bytes")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                v.try_into().map_err(|_| E::custom("invalid string"))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

impl JsonSchema for NonNulString {
    fn schema_name() -> String {
        "NonNulString".to_string()
    }

    fn json_schema(_: &mut SchemaGenerator) -> schemars::schema::Schema {
        SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            string: Some(Box::new(StringValidation {
                min_length: None,
                max_length: None,
                pattern: Some("not nul".into()),
            })),
            ..Default::default()
        }
        .into()
    }
}

#[test]
fn try_from() {
    assert!(NonNulString::try_from("hello").is_ok());
    assert!(NonNulString::try_from("hello🤡").is_ok());
}

#[test]
fn try_from_with_nul() {
    assert!(NonNulString::try_from("hel\0lo").is_err());
    assert!(NonNulString::try_from("\0hello").is_err());
    assert!(NonNulString::try_from("hello\0").is_err());
}

#[test]
fn serialize() {
    assert!(matches!(
        serde_json::to_string(&NonNulString::try_from("hello").unwrap()),
        Ok(s) if s == "\"hello\""
    ));
}

#[test]
fn deserialize() {
    assert!(matches!(
        serde_json::from_str::<NonNulString>("\"hello\""),
        Ok(n) if n == NonNulString::try_from("hello").unwrap()
    ));
    assert!(matches!(
        serde_json::from_str::<NonNulString>("\"a\0\""),
        Err(_)
    ));
}

#[test]
fn deserialize_with_nul() {
    assert!(serde_json::from_str::<NonNulString>("\"hel\0lo\"").is_err());
}

#[test]
fn schema() {
    schemars::schema_for!(NonNulString);
}
