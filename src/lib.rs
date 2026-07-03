// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
#![forbid(unsafe_code)]
//! Authenticated encryption resilient over interference channels:
//! `VT(interleave(RS(AEAD(data))))`. See `sbtdd/spec-behavior.md`.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_are_pinned() {
        assert_eq!(KEY_LEN, 32);
        assert_eq!(NONCE_LEN, 12);
        assert_eq!(TAG_LEN, 16);
        assert_eq!(MAX_PLAINTEXT_LEN, 10 * 1024 * 1024);
        assert_eq!(BLOB_VERSION, 1);
        assert_eq!(RS_DATA + RS_PARITY, RS_BLOCK);
        assert_eq!(RS_INTERLEAVE_MAX, 16);
        assert!(MAX_BLOB_LEN > MAX_PLAINTEXT_LEN);
    }
}
