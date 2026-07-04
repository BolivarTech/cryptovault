// Author: Julian Bolivar
// Version: 0.2.1
// Date: 2026-07-03
//! Authenticated cipher: the `AuthenticatedCipher` trait and the
//! `Aes256GcmSivCipher` AEAD with AAD binding (SR-C1 / SR-C4).
//!
//! The single security layer of the crate. AES-256-GCM-SIV (RFC 8452) provides
//! nonce-misuse-resistant authenticated encryption; the blob header is bound as
//! additional authenticated data (AAD) so that tampering beyond the FEC's
//! correction capacity fails the authentication tag rather than decrypting to
//! wrong-but-plausible plaintext. The FEC stack sits *after* this layer and adds
//! resilience, never security.

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::{CryptoError, Result};
use crate::{KEY_LEN, NONCE_LEN};

/// Sample a fresh [`crate::NONCE_LEN`]-byte AEAD nonce from the operating
/// system CSPRNG (`OsRng`) — a distinct nonce per encrypted record (SR-C1).
///
/// # Returns
/// A [`crate::NONCE_LEN`]-byte array filled with cryptographically secure
/// random bytes.
///
/// # Errors
/// [`CryptoError::Cipher`] if `OsRng` fails to produce entropy. On failure the
/// nonce is **never** returned zero/weak and the caller must abort the
/// encryption — the function neither panics nor yields a predictable nonce.
///
/// # Examples
/// ```
/// use cryptovault::cipher::sample_nonce;
/// let nonce = sample_nonce().unwrap();
/// assert_eq!(nonce.len(), 12);
/// ```
pub fn sample_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| CryptoError::Cipher(format!("OsRng nonce sampling failed: {e}")))?;
    Ok(nonce)
}

/// Strategy trait for authenticated encryption with associated data (AEAD).
///
/// Injectable so the audited [`Aes256GcmSivCipher`] default can be swapped for a
/// test double (e.g. a deterministic-nonce cipher) or a future algorithm.
/// Implementors MUST be `Send + Sync` so a `CryptoVault` can encrypt/decrypt
/// across threads. Every reversible operation is a matched `encrypt` / `decrypt`
/// pair over the same `(key, nonce, aad)` context.
pub trait AuthenticatedCipher: Send + Sync {
    /// Encrypt and authenticate `pt`, binding `aad` into the tag.
    ///
    /// # Parameters
    /// - `key`: the AEAD key (MUST be [`crate::KEY_LEN`] bytes).
    /// - `nonce`: the per-record nonce (MUST be [`crate::NONCE_LEN`] bytes).
    /// - `aad`: additional authenticated data (the blob header) — authenticated
    ///   but not encrypted.
    /// - `pt`: the plaintext to encrypt.
    ///
    /// # Returns
    /// The ciphertext with the [`crate::TAG_LEN`]-byte tag appended.
    ///
    /// # Errors
    /// [`CryptoError::Cipher`] if `key`/`nonce` are the wrong length or the
    /// cipher fails internally.
    fn encrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt and verify `ct` under the same `(key, nonce, aad)` used to
    /// [`encrypt`](Self::encrypt).
    ///
    /// # Parameters
    /// - `key`: the AEAD key (MUST be [`crate::KEY_LEN`] bytes).
    /// - `nonce`: the record nonce (MUST be [`crate::NONCE_LEN`] bytes).
    /// - `aad`: the additional authenticated data that was bound on encrypt.
    /// - `ct`: the ciphertext with the appended tag.
    ///
    /// # Returns
    /// The recovered plaintext.
    ///
    /// # Errors
    /// [`CryptoError::Cipher`] if `key`/`nonce` are the wrong length or the
    /// authentication tag fails (wrong key, wrong `aad`, or tampered `ct`). No
    /// key material is revealed on failure.
    fn decrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>>;

    /// The nonce length (bytes) this cipher expects.
    fn nonce_len(&self) -> usize;
}

/// Audited default [`AuthenticatedCipher`]: AES-256-GCM-SIV (RFC 8452), a
/// nonce-misuse-resistant AEAD with a 256-bit key and a 128-bit tag (SR-C1).
///
/// Fieldless strategy struct — construct directly as `Aes256GcmSivCipher` (no
/// `new` needed).
///
/// # Examples
/// ```
/// use cryptovault::cipher::{Aes256GcmSivCipher, AuthenticatedCipher};
/// let cipher = Aes256GcmSivCipher;
/// let ct = cipher.encrypt(&[0u8; 32], &[0u8; 12], b"header", b"data").unwrap();
/// let pt = cipher.decrypt(&[0u8; 32], &[0u8; 12], b"header", &ct).unwrap();
/// assert_eq!(pt, b"data");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Aes256GcmSivCipher;

impl Aes256GcmSivCipher {
    /// Build an AES-256-GCM-SIV instance from a caller-supplied key slice,
    /// validating the key length up front (DRY: shared by encrypt/decrypt).
    ///
    /// # Errors
    /// [`CryptoError::Cipher`] if `key.len() != KEY_LEN` — checked *before* any
    /// fixed-size conversion, so a wrong-length key never panics.
    fn cipher_for(key: &[u8]) -> Result<Aes256GcmSiv> {
        if key.len() != KEY_LEN {
            return Err(CryptoError::Cipher(format!(
                "AES-256 key must be {KEY_LEN} bytes, got {}",
                key.len()
            )));
        }
        // Length checked above, so `from_slice` cannot panic.
        Ok(Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key)))
    }

    /// Validate a nonce slice and view it as a fixed-size AEAD nonce.
    ///
    /// # Errors
    /// [`CryptoError::Cipher`] if `nonce.len() != NONCE_LEN` — checked *before*
    /// any fixed-size conversion, so a wrong-length nonce never panics.
    fn nonce_for(nonce: &[u8]) -> Result<&Nonce> {
        if nonce.len() != NONCE_LEN {
            return Err(CryptoError::Cipher(format!(
                "nonce must be {NONCE_LEN} bytes, got {}",
                nonce.len()
            )));
        }
        // Length checked above, so `from_slice` cannot panic.
        Ok(Nonce::from_slice(nonce))
    }
}

impl AuthenticatedCipher for Aes256GcmSivCipher {
    fn encrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        let cipher = Self::cipher_for(key)?;
        let nonce = Self::nonce_for(nonce)?;
        cipher
            .encrypt(nonce, Payload { msg: pt, aad })
            .map_err(|_| CryptoError::Cipher("AES-256-GCM-SIV encryption failed".into()))
    }

    fn decrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        let cipher = Self::cipher_for(key)?;
        let nonce = Self::nonce_for(nonce)?;
        cipher
            .decrypt(nonce, Payload { msg: ct, aad })
            .map_err(|_| CryptoError::Cipher("AES-256-GCM-SIV authentication failed".into()))
    }

    fn nonce_len(&self) -> usize {
        NONCE_LEN
    }
}

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
    fn test_sr_c1_nonce_is_random_and_sized() {
        let a = sample_nonce().unwrap();
        let b = sample_nonce().unwrap();
        assert_eq!(a.len(), NONCE_LEN);
        assert_ne!(a, b, "OsRng must not return a repeating/zero nonce");
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
        assert_eq!(
            ct, expected,
            "ciphertext||tag must match the RFC 8452 vector"
        );
        assert_eq!(c.decrypt(&key, &nonce, &aad, &ct).unwrap(), pt);
    }
}
