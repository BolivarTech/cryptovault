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

pub mod interleaver;
pub mod rs;
pub mod viterbi;

pub use interleaver::{BlockInterleaver, CsprngLayer, Interleaver};
pub use rs::ReedSolomonCodec;
pub use viterbi::ViterbiCodec;

use crate::error::Result;

/// Default interleave depth `I` (codewords per window) — CCSDS baseline (SR-F2).
const DEFAULT_INTERLEAVE_DEPTH: usize = 5;

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

/// The concatenated FEC stack — Red-phase stub.
///
/// Implemented in the Green phase; the stub exists only so the failing tests
/// compile and fail by assertion.
pub struct ConcatenatedFec {
    rs: ReedSolomonCodec,
    il: Interleaver,
    vt: ViterbiCodec,
}

impl ConcatenatedFec {
    /// Red-phase stub constructor.
    pub fn new(rs: ReedSolomonCodec, il: Interleaver, vt: ViterbiCodec) -> Self {
        Self { rs, il, vt }
    }
}

impl Default for ConcatenatedFec {
    fn default() -> Self {
        Self::new(
            ReedSolomonCodec,
            Interleaver::Block(
                BlockInterleaver::new(DEFAULT_INTERLEAVE_DEPTH)
                    .expect("DEFAULT_INTERLEAVE_DEPTH is in range"),
            ),
            ViterbiCodec,
        )
    }
}

impl ErrorCorrection for ConcatenatedFec {
    fn encode(&self, data: &[u8]) -> Vec<u8> {
        let _ = (&self.il, &self.vt);
        data.to_vec() // stub: identity, not the real pipeline
    }

    fn decode(&self, encoded: &[u8], pre_len: usize) -> Result<Vec<u8>> {
        let _ = (&self.rs, &self.il, &self.vt, encoded, pre_len);
        Ok(Vec::new()) // stub
    }
}

#[cfg(test)]
mod concatenated_tests {
    use super::{
        BlockInterleaver, ConcatenatedFec, ErrorCorrection, Interleaver, ReedSolomonCodec,
        ViterbiCodec,
    };
    use crate::error::CryptoError;
    use crate::RS_BLOCK;

    /// Builds the audited default stack via the explicit DI constructor (depth 5).
    fn di_stack() -> ConcatenatedFec {
        ConcatenatedFec::new(
            ReedSolomonCodec,
            Interleaver::Block(BlockInterleaver::new(5).unwrap()),
            ViterbiCodec,
        )
    }

    /// SR-F4 / SC-1: the audited `Default` stack and the DI-constructed stack both
    /// round-trip a multi-codeword payload exactly over a clean channel.
    #[test]
    fn test_sr_f4_sc1_clean_channel_roundtrip_default_and_injected() {
        let payload: Vec<u8> = (0..(3 * RS_BLOCK)).map(|i| (i * 5) as u8).collect();
        for fec in [ConcatenatedFec::default(), di_stack()] {
            let enc = fec.encode(&payload);
            assert_eq!(
                fec.decode(&enc, payload.len()).unwrap(),
                payload,
                "clean-channel round-trip recovers the exact payload"
            );
        }
    }

    /// SR-F4 / SC-2: a channel burst that the interleaver spreads to within the
    /// Reed-Solomon correction capacity is recovered exactly.
    #[test]
    fn test_sc2_noisy_within_capacity_recovers_exactly() {
        let fec = ConcatenatedFec::default();
        let payload: Vec<u8> = (0..(5 * RS_BLOCK)).map(|i| (i * 3 + 1) as u8).collect();
        let mut enc = fec.encode(&payload);
        // Inject a contiguous burst; the interleaver disperses it across codewords.
        let start = enc.len() / 3;
        for byte in enc.iter_mut().skip(start).take(24) {
            *byte ^= 0xFF;
        }
        assert_eq!(
            fec.decode(&enc, payload.len()).unwrap(),
            payload,
            "a within-capacity burst is corrected, payload recovered exactly"
        );
    }

    /// SR-F4 / SC-3: corruption beyond the concatenated code's capacity yields a
    /// typed error, never silently-wrong bytes.
    #[test]
    fn test_sc3_corruption_beyond_capacity_is_typed_error_not_silent() {
        let fec = ConcatenatedFec::default();
        let payload: Vec<u8> = (0..(2 * RS_BLOCK)).map(|i| (i * 7) as u8).collect();
        let mut enc = fec.encode(&payload);
        // Obliterate the first half of the blob — far beyond correction capacity.
        let half = enc.len() / 2;
        for byte in enc.iter_mut().take(half) {
            *byte ^= 0xFF;
        }
        let result = fec.decode(&enc, payload.len());
        // At the FEC layer, beyond-capacity corruption surfaces as a typed FEC or
        // structural error — never silently-wrong bytes (the AEAD tag is the final
        // backstop above this layer, SR-R6).
        assert!(
            matches!(
                result,
                Err(CryptoError::ErrorCorrection(_)) | Err(CryptoError::InvalidInput(_))
            ),
            "beyond-capacity decode must be a typed error, got {result:?}"
        );
    }
}
