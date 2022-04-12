use hmac::{
    digest::{generic_array::GenericArray, CtOutput},
    Mac,
};
use lazy_static::lazy_static;
use rand_core::{OsRng, RngCore};
use serde::{de::Visitor, Deserialize, Serialize, Serializer};
use sha2::Sha256;
use std::{fmt, time::Instant};

// Tokens are valid for one minute
pub const TOKEN_EXPIRED_THRESHOLD: Timestamp = 60_000; // 60 seconds

lazy_static! {
    static ref MAC_KEY: [u8; 32] = {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    };
    static ref FIRST_TOKEN_TIME: Instant = Instant::now();
}

pub type Timestamp = u128;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Token {
    time: Timestamp,
    hmac: Hmac,
}

type HmacSha256 = hmac::Hmac<Sha256>;

impl Token {
    pub fn new(usage: &str) -> Token {
        let time = Token::current_time();
        let hmac = Token::calculate_hmac(&time, usage);
        Token { time, hmac }
    }

    pub fn verify(&self, usage: &str) -> bool {
        let hmac = Token::calculate_hmac(&self.time, usage);
        let is_authentic = self.hmac == hmac; // constant time comparison ensured by CtOutput
        let is_expired = Token::current_time()
            .checked_sub(self.time)
            .map_or(true, |age| age > TOKEN_EXPIRED_THRESHOLD);
        is_authentic && !is_expired
    }

    pub fn write<T: std::io::Write>(&self, output: &mut T) -> std::io::Result<()> {
        let time = self.time.to_be_bytes();
        let hmac = self.hmac.clone().into_bytes();
        output.write_all(&time)?;
        output.write_all(&hmac)?;
        Ok(())
    }

    fn calculate_hmac(time: &Timestamp, usage: &str) -> Hmac {
        let mut hasher = HmacSha256::new_from_slice(MAC_KEY.as_slice())
            .expect("Failed to create SHA-256 hasher");
        hasher.update(&time.to_be_bytes());
        hasher.update(usage.as_bytes());
        Hmac(hasher.finalize())
    }

    fn current_time() -> Timestamp {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Clock is earlier than UNIX Epoch")
            .as_millis()
    }
}

#[derive(PartialEq)]
struct Hmac(CtOutput<HmacSha256>);

impl fmt::Debug for Hmac {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\"{}\"", hex::encode(self.0.clone().into_bytes()))
    }
}

impl std::ops::Deref for Hmac {
    type Target = CtOutput<HmacSha256>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for Hmac {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0.clone().into_bytes()))
    }
}

impl<'de> Deserialize<'de> for Hmac {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HashVisitor;

        impl<'de> Visitor<'de> for HashVisitor {
            type Value = CtOutput<HmacSha256>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a 32 byte sequence")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let decoded = hex::decode(v).map_err(serde::de::Error::custom)?;
                Ok(CtOutput::<HmacSha256>::new(GenericArray::clone_from_slice(
                    &decoded,
                )))
            }
        }

        Ok(Hmac(deserializer.deserialize_str(HashVisitor)?))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const USAGE: &str = "MQTT";

    #[test]
    fn verify_new_token() {
        assert!(Token::new(USAGE).verify(USAGE));
    }

    #[test]
    fn verify_recent_token() {
        let mut recent_token = Token::new(USAGE);
        recent_token.time = recent_token
            .time
            .checked_sub(1000 * 10) // 10 seconds into the past
            .expect("Failed to create future timestamp");
        recent_token.hmac = Token::calculate_hmac(&recent_token.time, USAGE); // Fix HMAC for changed timestamp
        assert!(recent_token.verify(USAGE));
    }

    #[test]
    fn verify_old_token() {
        const ONE_HOUR_IN_MS: Timestamp = 24 * 60 * 60 * 1000;
        let mut old_token = Token::new(USAGE);
        old_token.time = old_token
            .time
            .checked_sub(ONE_HOUR_IN_MS)
            .expect("Failed to create future timestamp");
        old_token.hmac = Token::calculate_hmac(&old_token.time, USAGE); // Fix HMAC for changed timestamp
        assert!(!old_token.verify(USAGE));
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
        let mut broken_mac = broken_token.hmac.clone().into_bytes().to_vec();
        broken_mac[0] = broken_mac[0].overflowing_add(1).0;
        let broken_mac: [u8; 32] = broken_mac.try_into().unwrap();
        broken_token.hmac = Hmac(CtOutput::<HmacSha256>::new(GenericArray::clone_from_slice(
            &broken_mac,
        )));
        assert!(!broken_token.verify(USAGE));
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
        assert!(Token::new(USAGE).write(&mut output.as_mut_slice()).is_err());
    }

    #[test]
    fn token_serde_roundtrip() {
        let token = Token::new(USAGE);
        let serialized = serde_json::to_string(&token).unwrap();
        let deserialized: Token = serde_json::from_str(&serialized).unwrap();
        assert_eq!(token, deserialized);
    }
}
