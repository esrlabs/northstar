use hmac::{
    digest::{generic_array::GenericArray, CtOutput},
    Mac,
};
use lazy_static::lazy_static;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::{
    fmt,
    time::{self, Instant},
};

use crate::api;

// Tokens are valid for one minute
const TOKEN_EXPIRED_THRESHOLD: time::Duration = time::Duration::from_secs(60);

lazy_static! {
    static ref MAC_KEY: [u8; 32] = {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    };
    /// Use Instant as a monotonic clock source
    static ref START_TIMESTAMP: Instant = Instant::now();
}

type HmacSha256 = hmac::Hmac<Sha256>;
type Hmac = CtOutput<HmacSha256>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VerificationResult {
    /// Verification succeeded
    Valid,
    /// Verification failed
    Invalid,
    /// Token is expired
    Expired,
}

/// Token instance
#[derive(Clone, PartialEq)]
pub(crate) struct Token {
    time: time::Duration,
    hmac: Hmac,
}

impl Token {
    /// Create a new token
    pub fn new<T: AsRef<[u8]>>(usage: T) -> Token {
        let now = now();
        let hmac = calculate_hmac(&now, usage);
        Token { time: now, hmac }
    }

    /// Verify that `usage` matches the token
    pub fn verify<T: AsRef<[u8]>>(&self, usage: T) -> VerificationResult {
        if now()
            .checked_sub(self.time)
            .map_or(true, |age| age > TOKEN_EXPIRED_THRESHOLD)
        {
            VerificationResult::Expired
        } else if calculate_hmac(&self.time, usage) == self.hmac {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid
        }
    }
}

fn now() -> time::Duration {
    let now = Instant::now().duration_since(*START_TIMESTAMP);
    time::Duration::from_secs(now.as_secs()) // round to seconds
}

fn calculate_hmac<T: AsRef<[u8]>>(time: &time::Duration, usage: T) -> Hmac {
    let mut hasher =
        HmacSha256::new_from_slice(MAC_KEY.as_slice()).expect("Failed to create SHA-256 hasher");
    hasher.update(&time.as_millis().to_be_bytes());
    hasher.update(usage.as_ref());
    hasher.finalize()
}

impl From<[u8; 40]> for Token {
    fn from(bytes: [u8; 40]) -> Self {
        let mut time = [0u8; 8];
        time.copy_from_slice(&bytes[..8]);
        let time = time::Duration::from_secs(u64::from_be_bytes(time));
        let hmac = CtOutput::<HmacSha256>::new(GenericArray::clone_from_slice(&bytes[8..]));
        Token { time, hmac }
    }
}

impl From<Token> for [u8; 40] {
    fn from(token: Token) -> Self {
        let mut bytes = [0u8; 40];
        bytes[..8].copy_from_slice(&token.time.as_secs().to_be_bytes());
        bytes[8..].copy_from_slice(&token.hmac.into_bytes());
        bytes
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("time", &self.time)
            .field("hmac", &self.hmac.clone().into_bytes())
            .finish()
    }
}

impl From<VerificationResult> for api::model::VerificationResult {
    fn from(result: VerificationResult) -> Self {
        match result {
            VerificationResult::Valid => api::model::VerificationResult::Valid,
            VerificationResult::Invalid => api::model::VerificationResult::Invalid,
            VerificationResult::Expired => api::model::VerificationResult::Expired,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const USAGE: &str = "hello";

    #[test]
    fn verify_new_token() {
        assert_eq!(Token::new(USAGE).verify(USAGE), VerificationResult::Valid);
    }

    #[test]
    fn verify_recent_token() {
        let mut recent_token = Token::new(USAGE);
        recent_token.time = recent_token
            .time
            .checked_sub(time::Duration::from_secs(10)) // 10 seconds into the past
            .expect("Failed to create future timestamp");
        recent_token.hmac = calculate_hmac(&recent_token.time, USAGE); // Fix HMAC for changed timestamp
        assert_eq!(recent_token.verify(USAGE), VerificationResult::Valid);
    }

    #[test]
    fn verify_old_token() {
        let mut old_token = Token::new(USAGE);
        old_token.time = old_token
            .time
            .checked_sub(time::Duration::from_secs(3600)) // 1 hour into the past
            .expect("Failed to create future timestamp");
        old_token.hmac = calculate_hmac(&old_token.time, USAGE); // Fix HMAC for changed timestamp
        assert_eq!(old_token.verify(USAGE), VerificationResult::Expired);
    }

    #[test]
    fn verify_future_token() {
        let mut future_token = Token::new(USAGE);
        future_token.time = future_token
            .time
            .checked_add(time::Duration::from_millis(1))
            .expect("Failed to create future timestamp");
        assert_eq!(future_token.verify(USAGE), VerificationResult::Expired);
    }

    #[test]
    fn verify_broken_mac() {
        let mut broken_token = Token::new(USAGE);
        let mut broken_mac = broken_token.hmac.clone().into_bytes().to_vec();
        broken_mac[0] = broken_mac[0].overflowing_add(1).0;
        let broken_mac: [u8; 32] = broken_mac.try_into().unwrap();
        broken_token.hmac =
            CtOutput::<HmacSha256>::new(GenericArray::clone_from_slice(&broken_mac));
        assert_eq!(broken_token.verify(USAGE), VerificationResult::Invalid);
    }

    #[test]
    fn verify_wrong_usage() {
        assert_eq!(
            Token::new(USAGE).verify("XMPP"),
            VerificationResult::Invalid
        );
    }

    #[test]
    fn byte_array_roundtrip() {
        let original = Token::new(USAGE);
        let bytes: [u8; 40] = original.clone().into();
        let token: Token = bytes.into();
        assert_eq!(original, token);
    }
}
