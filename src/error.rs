// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Typed error domain for the vault: the single `CryptoError` enum and its
//! `Result` alias (SR-R7).
//!
//! Every fallible operation in the crate returns [`Result<T>`], and every error
//! surfaces as one typed [`CryptoError`] variant — no silent failures, no
//! panics on adversarial input. Decode-path errors deliberately carry no
//! interleaver-internal detail (SR-R7): the message names the failing stage
//! (cipher / error-correction / structural), never a permutation oracle.

use core::fmt;

/// Crate-wide result alias — every fallible operation returns this (SR-R7).
pub type Result<T> = core::result::Result<T, CryptoError>;

/// The single typed error domain for the vault (SR-R7).
///
/// One variant per failing stage so callers can distinguish a channel error
/// (worth a retransmit) from a wrong-key / structural error (not worth one),
/// while the AEAD prevents forgery regardless of which is surfaced. Each
/// variant carries a human-readable, oracle-free message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Key-derivation failure — raised by the Argon2id master derivation and
    /// HKDF sub-key expansion (SR-C2 / SR-C3): invalid Argon2 parameters,
    /// output-length mismatch, or an HKDF expand failure.
    KeyDerivation(String),

    /// AEAD failure — raised by AES-256-GCM-SIV encrypt/decrypt (SR-C1 / SR-C4):
    /// a failed authentication tag (wrong key, wrong AAD, or tampered
    /// ciphertext), a cipher-init error, or an `OsRng` nonce-sampling failure.
    /// No key material is revealed.
    Cipher(String),

    /// Forward-error-correction failure — raised by the concatenated FEC stack
    /// (SR-F1 / SR-F3): corruption beyond the Reed-Solomon / Viterbi correction
    /// capacity. Decode is all-or-nothing; an uncorrectable block fails loud.
    ErrorCorrection(String),

    /// Encoding failure — raised by base64 decoding (SR-F6): a non-canonical
    /// alphabet, bad padding, or trailing bits are rejected rather than
    /// silently accepted.
    Encoding(String),

    /// Structural / input-validation failure — raised before any FEC decode
    /// (SR-R3 / SR-R4 / SR-R6): oversized input, a blob length inconsistent
    /// with the Viterbi/RS framing, an empty password, a wrong-length salt, or
    /// an out-of-range parameter. Guards against allocation DoS and panics.
    InvalidInput(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::KeyDerivation(m) => write!(f, "Key derivation error: {m}"),
            CryptoError::Cipher(m) => write!(f, "Cipher error: {m}"),
            CryptoError::ErrorCorrection(m) => write!(f, "Error correction error: {m}"),
            CryptoError::Encoding(m) => write!(f, "Encoding error: {m}"),
            CryptoError::InvalidInput(m) => write!(f, "Invalid input: {m}"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sr_r7_error_variants_display_and_are_typed() {
        let e = CryptoError::InvalidInput("bad len".into());
        assert!(e.to_string().to_lowercase().contains("invalid"));
        assert!(matches!(e, CryptoError::InvalidInput(_)));
    }
}
