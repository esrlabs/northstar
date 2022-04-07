use lazy_static::lazy_static;
use rand_core::{OsRng, RngCore};
use serde::{de::Visitor, Deserialize, Serialize, Serializer};
use std::{
    fmt,
    ops::Add,
    time::{Duration, Instant},
};

// Tokens are valid for one minute
const TOKEN_EXPIRED_THRESHOLD: Duration = Duration::from_secs(60);

lazy_static! {
    static ref MAC_KEY: [u8; 32] = {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    };
    static ref FIRST_TOKEN_TIME: Instant = Instant::now();
}

pub type Timestamp = u64;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Token {
    time: Timestamp,
    mac: Hash,
}

impl Token {
    pub fn new(usage: &str) -> Token {
        let first = *FIRST_TOKEN_TIME; // Do not inline to ensure earliest initialization
        let time = Instant::now().duration_since(first).as_secs();
        let mac = Token::calculate_mac(&time, usage);
        Token { time, mac }
    }

    pub fn verify(&self, usage: &str) -> bool {
        // Check MAC
        let mac = Token::calculate_mac(&self.time, usage);
        if self.mac != mac {
            return false;
        }

        // Check expiration
        let token_time = FIRST_TOKEN_TIME.add(Duration::from_secs(self.time));
        if token_time < *FIRST_TOKEN_TIME {
            return false; // Token is older than the very first one
        }
        let token_age = Instant::now().duration_since(token_time);
        token_age <= TOKEN_EXPIRED_THRESHOLD
    }

    pub fn write<T: std::io::Write>(&self, output: &mut T) -> std::io::Result<()> {
        let time = self.time.to_be_bytes();
        let mac = self.mac.as_bytes();
        output.write_all(&time)?;
        output.write_all(mac)?;
        Ok(())
    }

    fn calculate_mac(time: &Timestamp, usage: &str) -> Hash {
        let mut hasher = blake3::Hasher::new_keyed(&MAC_KEY);
        hasher.update(&time.to_be_bytes());
        hasher.update(usage.as_bytes());
        Hash(hasher.finalize())
    }
}

#[derive(PartialEq)]
struct Hash(blake3::Hash);

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.to_hex())
    }
}

impl std::ops::Deref for Hash {
    type Target = blake3::Hash;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&*self.0.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HashVisitor;

        impl<'de> Visitor<'de> for HashVisitor {
            type Value = blake3::Hash;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a 32 byte sequence")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                blake3::Hash::from_hex(v).map_err(serde::de::Error::custom)
            }
        }

        Ok(Hash(deserializer.deserialize_str(HashVisitor)?))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use blake3::OUT_LEN;

    const USAGE: &str = "MQTT";

    #[test]
    fn verify_new_token() {
        assert!(Token::new(USAGE).verify(USAGE));
    }

    #[test]
    fn verify_future_token() {
        let mut future_token = Token::new(USAGE);
        future_token.time = future_token
            .time
            .checked_add(1)
            .expect("Failed to create future timestamp");
        assert!(!future_token.verify("XMPP"));
    }

    #[test]
    fn verify_broken_mac() {
        let mut broken_token = Token::new(USAGE);
        let mut broken_mac = broken_token.mac.as_bytes().to_vec();
        broken_mac[0] = broken_mac[0].overflowing_add(1).0;
        let broken_mac: [u8; OUT_LEN] = broken_mac.try_into().unwrap();
        broken_token.mac = Hash(broken_mac.into());
        assert!(!broken_token.verify("XMPP"));
    }

    #[test]
    fn verify_wrong_usage() {
        assert!(!Token::new(USAGE).verify("XMPP"));
    }

    #[test]
    fn write_token() {
        let mut output = [0u8; 40];
        assert!(Token::new(USAGE)
            .write(&mut std::io::BufWriter::new(output.as_mut_slice()))
            .is_ok());
    }

    #[test]
    fn write_token_to_short_buffer() {
        let mut output = [0u8; 39];
        assert!(Token::new("MQTT")
            .write(&mut output.as_mut_slice())
            .is_err());
    }

    #[test]
    fn token_serde_roundtrip() {
        let token = Token::new(USAGE);
        let serialized = serde_json::to_string(&token).unwrap();
        let deserialized: Token = serde_json::from_str(&serialized).unwrap();
        assert_eq!(token, deserialized);
    }
}
