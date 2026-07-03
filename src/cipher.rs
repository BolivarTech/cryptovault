// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Authenticated cipher: the `AuthenticatedCipher` trait and the
//! `Aes256GcmSivCipher` AEAD with AAD binding (implemented in Tasks 4-5,
//! SR-C1/C4).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CryptoError;
    use crate::{KEY_LEN, NONCE_LEN};

    /// Decode a compact hex string (whitespace ignored) into bytes so the RFC
    /// 8452 vectors can be pasted verbatim in the KAT below.
    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_sr_c1_c4_aead_roundtrip_with_aad_and_tamper_detection() {
        let c = Aes256GcmSivCipher;
        let (k, n, aad) = ([1u8; KEY_LEN], [2u8; NONCE_LEN], b"hdr".as_slice());
        let ct = c.encrypt(&k, &n, aad, b"secret").unwrap();
        assert_eq!(c.decrypt(&k, &n, aad, &ct).unwrap(), b"secret");
        // SR-C4: wrong AAD fails the tag.
        assert!(matches!(
            c.decrypt(&k, &n, b"HDR", &ct),
            Err(CryptoError::Cipher(_))
        ));
    }

    #[test]
    fn test_sr_c1_wrong_key_and_nonce_length_are_typed_not_panic() {
        let c = Aes256GcmSivCipher;
        // Wrong-length key/nonce must be rejected as a typed error, never panic.
        assert!(matches!(
            c.encrypt(&[0u8; KEY_LEN - 1], &[0u8; NONCE_LEN], b"", b"x"),
            Err(CryptoError::Cipher(_))
        ));
        assert!(matches!(
            c.encrypt(&[0u8; KEY_LEN], &[0u8; NONCE_LEN + 1], b"", b"x"),
            Err(CryptoError::Cipher(_))
        ));
        assert_eq!(c.nonce_len(), NONCE_LEN);
    }

    #[test]
    fn test_sr_f5_rfc8452_aes256gcmsiv_known_answer() {
        // RFC 8452 Appendix C.2 — AEAD_AES_256_GCM_SIV, non-empty PT + AAD.
        let key = hex("01000000000000000000000000000000 00000000000000000000000000000000");
        let nonce = hex("030000000000000000000000");
        let aad = hex("01000000000000000000000000000000 02000000");
        let pt = hex("03000000000000000000000000000000 0400");
        let expected =
            hex("462401724b5ce6588d5a54aae5375513 a075cfcdf5042112aa29685c912fc205 6543");

        let c = Aes256GcmSivCipher;
        let ct = c.encrypt(&key, &nonce, &aad, &pt).unwrap();
        assert_eq!(ct, expected, "ciphertext||tag must match the RFC 8452 vector");
        assert_eq!(c.decrypt(&key, &nonce, &aad, &ct).unwrap(), pt);
    }
}
