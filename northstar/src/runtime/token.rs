use hmac::{
    digest::{generic_array::GenericArray, CtOutput},
    Mac,
};
use lazy_static::lazy_static;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::{
    fmt,
    time::{self},
};

use crate::api;

lazy_static! {
    static ref MAC_KEY: [u8; 32] = {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    };
    static ref START: time::Instant = {
        #[cfg(test)]
        {
            time::Instant::now() - time::Duration::from_secs(120)
        }
        #[cfg(not(test))]
        {
            time::Instant::now()
        }
    };
}

type HmacSha256 = hmac::Hmac<Sha256>;
type Hmac = CtOutput<HmacSha256>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VerificationResult {
    /// Verification succeeded
    Ok,
    /// Verification failed
    Invalid,
    /// Token is expired
    Expired,
    /// Token time is in the future
    Future,
}

/// Token instance
#[derive(Clone, PartialEq)]
pub(crate) struct Token {
    /// Duration how long the token is valid once created
    validity: time::Duration,
    /// Creatin time
    time: time::Duration,
    /// HMAC
    hmac: Hmac,
}

impl Token {
    /// Create a new token
    pub fn new<U, T, S>(validity: time::Duration, user: U, target: T, shared: S) -> Token
    where
        U: AsRef<[u8]>,
        T: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        let now = now();
        let hmac = calculate_hmac(&now, user.as_ref(), target.as_ref(), shared.as_ref());
        Token {
            validity,
            time: now,
            hmac,
        }
    }

    /// Verify that `shared` matches the token
    pub fn verify<U, T, S>(&self, user: U, target: T, shared: S) -> VerificationResult
    where
        U: AsRef<[u8]>,
        T: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        let now = now();

        if now < self.time {
            VerificationResult::Future
        } else if now - self.time > self.validity {
            VerificationResult::Expired
        } else if calculate_hmac(&self.time, user.as_ref(), target.as_ref(), shared.as_ref())
            == self.hmac
        {
            VerificationResult::Ok
        } else {
            VerificationResult::Invalid
        }
    }
}

fn now() -> time::Duration {
    time::Duration::from_secs(START.elapsed().as_secs())
}

fn calculate_hmac(time: &time::Duration, user: &[u8], target: &[u8], shared: &[u8]) -> Hmac {
    let mut hmac = HmacSha256::new_from_slice(MAC_KEY.as_slice())
        .expect("Failed to create SHA-256 HMAC instance");
    hmac.update(user);
    let user = hmac.finalize_reset();
    hmac.update(target);
    let target = hmac.finalize_reset();
    hmac.update(shared);
    let shared = hmac.finalize_reset();
    hmac.update(&time.as_millis().to_be_bytes());
    hmac.update(&user.into_bytes());
    hmac.update(&target.into_bytes());
    hmac.update(&shared.into_bytes());
    hmac.finalize()
}

impl From<(time::Duration, [u8; 40])> for Token {
    fn from((validity, bytes): (time::Duration, [u8; 40])) -> Self {
        let mut time = [0u8; 8];
        time.copy_from_slice(&bytes[..8]);
        let time = time::Duration::from_secs(u64::from_be_bytes(time));
        let hmac = CtOutput::<HmacSha256>::new(GenericArray::clone_from_slice(&bytes[8..]));
        Token {
            validity,
            time,
            hmac,
        }
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
            VerificationResult::Ok => api::model::VerificationResult::Ok,
            VerificationResult::Invalid => api::model::VerificationResult::Invalid,
            VerificationResult::Expired => api::model::VerificationResult::Expired,
            VerificationResult::Future => api::model::VerificationResult::Future,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::time::Duration;

    use super::*;

    const SHARED: &[u8] = b"hello";
    const USER: &[u8] = b"user";
    const TARGET: &[u8] = b"target";
    const VALIDITY: Duration = Duration::from_secs(60);

    #[test]
    fn verify_new() {
        assert_eq!(
            Token::new(VALIDITY, USER, TARGET, SHARED).verify(USER, TARGET, SHARED),
            VerificationResult::Ok
        );
    }

    #[test]
    fn verify_recent() {
        let mut recent_token = Token::new(VALIDITY, USER, TARGET, SHARED);
        recent_token.time = now() - recent_token.validity / 2;
        recent_token.hmac = calculate_hmac(&recent_token.time, USER, TARGET, SHARED); // Fix HMAC for changed timestamp
        assert_eq!(
            recent_token.verify(USER, TARGET, SHARED),
            VerificationResult::Ok
        );
    }

    #[test]
    fn verify_expired() {
        let mut old_token = Token::new(VALIDITY, USER, TARGET, SHARED);
        old_token.time = time::Duration::from_secs(0);
        old_token.hmac = calculate_hmac(&old_token.time, USER, TARGET, SHARED); // Fix HMAC for changed timestamp
        assert_eq!(
            old_token.verify(USER, TARGET, SHARED),
            VerificationResult::Expired
        );
    }

    #[test]
    fn verify_future() {
        let mut future_token = Token::new(VALIDITY, USER, TARGET, SHARED);
        future_token.time = now() + time::Duration::from_secs(3600);
        assert_eq!(
            future_token.verify(USER, TARGET, SHARED),
            VerificationResult::Future
        );
    }

    #[test]
    fn verify_broken_mac() {
        let mut broken_token = Token::new(VALIDITY, USER, TARGET, SHARED);
        let mut broken_mac = broken_token.hmac.clone().into_bytes().to_vec();
        broken_mac[0] = broken_mac[0].overflowing_add(1).0;
        let broken_mac: [u8; 32] = broken_mac.try_into().unwrap();
        broken_token.hmac =
            CtOutput::<HmacSha256>::new(GenericArray::clone_from_slice(&broken_mac));
        assert_eq!(
            broken_token.verify(USER, TARGET, SHARED),
            VerificationResult::Invalid
        );
    }

    #[test]
    fn verify_wrong_shared() {
        assert_eq!(
            Token::new(VALIDITY, USER, TARGET, SHARED).verify(USER, TARGET, "XMPP"),
            VerificationResult::Invalid
        );
    }

    #[test]
    fn byte_array_roundtrip() {
        let original = Token::new(VALIDITY, USER, TARGET, SHARED);
        let bytes: [u8; 40] = original.clone().into();
        let token: Token = (VALIDITY, bytes).into();
        assert_eq!(original, token);
    }
}
