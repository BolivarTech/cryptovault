// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Forward error correction: the [`ErrorCorrection`] strategy trait and the
//! concatenated FEC stack composing Reed-Solomon, interleaving, and Viterbi
//! (SR-F1 / SR-F2 / SR-F3 / SR-F4).
//!
//! The FEC layer is **resilience, not security** — it sits *after* the AEAD in
//! the pipeline and only lets a ciphertext survive a noisy channel; it never
//! provides confidentiality or integrity. Correction is **all-or-nothing**:
//! within the code's capacity a blob is recovered exactly, and past it the
//! decode fails loud (a typed [`crate::error::CryptoError`]), never returning
//! wrong-but-plausible bytes — the AEAD tag is the final integrity anchor.

pub mod rs;

pub use rs::ReedSolomonCodec;

use crate::error::Result;

/// A reversible forward-error-correction stage (SR-F1 / SR-F4).
///
/// Implementors are strategy objects composed into the vault behind a trait
/// object, so the FEC algorithm can be swapped (tests, an AEAD-only `NoFec`
/// mode, future algorithm rotation) without touching the crypto core. The pair
/// is symmetric: [`encode`](Self::encode) is inverted by
/// [`decode`](Self::decode).
///
/// `Send + Sync` so a shared vault can encode/decode concurrently — an
/// implementor holds immutable configuration only, never per-call state.
pub trait ErrorCorrection: Send + Sync {
    /// Error-correction-encodes `data`, returning the protected stream.
    ///
    /// This is the transmit (encrypt-side) path over the caller's own data, so
    /// it is infallible by contract: any implementor whose backing codec can
    /// fail must only do so on statically unreachable conditions (documented at
    /// the call site).
    ///
    /// # Parameters
    /// - `data`: the bytes to protect (at the blob layer, the AEAD payload).
    ///
    /// # Returns
    /// The encoded stream. Its length is implementation-defined but, for the
    /// Reed-Solomon codec, is always a whole multiple of [`crate::RS_BLOCK`].
    fn encode(&self, data: &[u8]) -> Vec<u8>;

    /// Error-corrects `encoded` and truncates the recovered stream to `pre_len`.
    ///
    /// # Parameters
    /// - `encoded`: the received, possibly-corrupted protected stream.
    /// - `pre_len`: the pre-encode length to truncate the recovered bytes to (at
    ///   the blob layer this is the derived `protected_len`, **never** the
    ///   header's `plaintext_len`).
    ///
    /// # Errors
    /// - [`crate::error::CryptoError::InvalidInput`] if `encoded` is
    ///   structurally invalid (e.g. not a whole number of codewords) — rejected
    ///   before the backing codec runs, so adversarial input never panics.
    /// - [`crate::error::CryptoError::ErrorCorrection`] if corruption exceeds the
    ///   code's correction capacity.
    fn decode(&self, encoded: &[u8], pre_len: usize) -> Result<Vec<u8>>;
}
