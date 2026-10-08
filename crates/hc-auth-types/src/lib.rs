//! Values shared by `hc-auth-server` and its clients.
//!
//! This crate has no dependencies, so a client can use it without the server.

/// Prefix a client puts before the `/now` payload, so the signature is valid for this purpose only.
pub const CHALLENGE_SIGNING_PREFIX: &[u8] = b"hc-auth-challenge-v1:";

/// Length in bytes of a decoded `/now` payload: an 8 byte timestamp and a 24 byte nonce.
pub const CHALLENGE_LEN: usize = 32;

/// The bytes a client signs for a `/now` payload: [`CHALLENGE_SIGNING_PREFIX`]
/// followed by the decoded payload.
///
/// The payload has a fixed length, so the server chooses [`CHALLENGE_LEN`] bytes
/// of what a client signs and nothing else.
pub fn challenge_signing_bytes(payload: &[u8; CHALLENGE_LEN]) -> Vec<u8> {
    [CHALLENGE_SIGNING_PREFIX, payload].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_bytes_are_the_prefix_then_the_payload() {
        let payload = [3u8; CHALLENGE_LEN];

        let bytes = challenge_signing_bytes(&payload);

        assert_eq!(bytes.len(), CHALLENGE_SIGNING_PREFIX.len() + CHALLENGE_LEN);
        assert!(bytes.starts_with(CHALLENGE_SIGNING_PREFIX));
        assert!(bytes.ends_with(&payload));
    }
}
