// Author: Julian Bolivar
// Version: 0.2.0
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

use crate::blob::validate_pre_fec;
use crate::error::{CryptoError, Result};
use crate::{RS_BLOCK, RS_DATA};

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

    /// Validates a received blob's framing **before** any FEC decode and returns
    /// the pre-decode payload length to recover (SR-R3a / SR-R4).
    ///
    /// This is the **strategy-owned** structural gate on the decrypt path: each
    /// codec knows its own wire framing, so the blob layer
    /// (`decode_blob`) delegates here instead of hard-coding the
    /// concatenated-FEC chunk math — that math would reject a blob produced by a
    /// different strategy (e.g. the identity [`crate::vault::NoFec`], whose blob
    /// is a raw protected payload with no FEC structure). The gate caps
    /// `received.len() <= `[`crate::MAX_BLOB_LEN`] to bound allocation and
    /// **never panics** on adversarial input.
    ///
    /// # Parameters
    /// - `received`: the raw received blob (post-base64-decode).
    ///
    /// # Returns
    /// The pre-decode length to pass as `pre_len` to [`decode`](Self::decode):
    /// for the Reed-Solomon-based codecs the recovered RS data length, for
    /// [`crate::vault::NoFec`] the received length itself.
    ///
    /// # Errors
    /// [`crate::error::CryptoError::InvalidInput`] if `received` is oversized
    /// (`> `[`crate::MAX_BLOB_LEN`]) or structurally malformed for this codec.
    fn validate_pre_fec(&self, received: &[u8]) -> Result<usize>;
}

/// The concatenated forward-error-correction stack (SR-F4).
///
/// Composes the three FEC stages behind the [`ErrorCorrection`] trait in the
/// spec's pipeline order — Reed-Solomon (outer) → interleaver → Viterbi (inner):
///
/// ```text
/// encode:  data ── RS ──▶ interleave ──▶ Viterbi ──▶ blob
/// decode:  blob ── Viterbi ──▶ deinterleave ──▶ RS ──▶ data
/// ```
///
/// It is **resilience, not security**: it sits *after* the AEAD and only lets a
/// ciphertext survive a noisy channel. The stages are injected, so a test or an
/// AEAD-only mode can swap any of them; [`ConcatenatedFec::default`] wires the
/// audited defaults (RS(255,223), a depth-5 deterministic block interleaver, and
/// the CCSDS `K=7 R=1/2` Viterbi codec).
///
/// # Examples
///
/// ```
/// use cryptovault::fec::{ConcatenatedFec, ErrorCorrection};
///
/// let fec = ConcatenatedFec::default();
/// let data: Vec<u8> = (0..600u32).map(|i| i as u8).collect();
/// let blob = fec.encode(&data);
/// assert_eq!(fec.decode(&blob, data.len()).unwrap(), data); // clean round-trip
/// ```
pub struct ConcatenatedFec {
    /// Outer Reed-Solomon `RS(255,223)` code.
    rs: ReedSolomonCodec,
    /// Burst-spreading interleaver (deterministic block, optionally + CSPRNG).
    il: Interleaver,
    /// Inner CCSDS `K=7 R=1/2` Viterbi convolutional code.
    vt: ViterbiCodec,
}

impl ConcatenatedFec {
    /// Composes a concatenated FEC stack from injected stages (SR-F4).
    ///
    /// The dependency-injection constructor: pass custom stages for tests, an
    /// AEAD-only configuration, or future algorithm rotation.
    /// [`ConcatenatedFec::default`] wires the audited defaults instead.
    ///
    /// # Parameters
    /// - `rs`: the outer Reed-Solomon codec.
    /// - `il`: the interleaving stage.
    /// - `vt`: the inner Viterbi codec.
    ///
    /// # Returns
    /// The composed stack.
    #[must_use]
    pub fn new(rs: ReedSolomonCodec, il: Interleaver, vt: ViterbiCodec) -> Self {
        Self { rs, il, vt }
    }

    /// Builds a concatenated FEC stack with the **optional CSPRNG obfuscation
    /// layer** enabled, deriving its interleaver seed from a session `master`
    /// (L12, SR-C3 / SR-F2).
    ///
    /// This is the ergonomic, domain-separation-enforcing path to the
    /// [`Interleaver::BlockThenCsprng`] variant: it HKDF-expands `master` into the
    /// `cryptovault:v1:interleaver` sub-key (via
    /// [`expand_interleaver_seed`](crate::kdf::expand_interleaver_seed)) and wires
    /// it into a [`CsprngLayer`], so a caller gets the same key hierarchy the vault
    /// enforces internally — the seed is **never** the raw AEAD key — instead of
    /// hand-wiring `HKDF → CsprngLayer → Interleaver` themselves. Inject the result
    /// into [`CryptoVault::new`](crate::vault::CryptoVault::new) as the FEC
    /// strategy; both encrypt and decrypt sides must build the stack from the
    /// **same** `master` and `depth` so the permutation matches.
    ///
    /// # ⚠️ Opt-in, non-security defense-in-depth
    ///
    /// The CSPRNG layer is **obfuscation, not security** (gradation
    /// `fixed < CSPRNG < AEAD`): confidentiality and integrity come **only** from
    /// the AEAD applied first. Enabling it also **weakens** the deterministic block
    /// interleaver's worst-case burst-spreading guarantee (quantified in
    /// `docs/interleaver-csprng-degradation.md`) and introduces the DC-1
    /// static-per-key-permutation limitation (crate-level docs). Prefer the default
    /// [`ConcatenatedFec::default`] (block-only) unless you have a concrete reason
    /// for the extra obfuscation.
    ///
    /// # Parameters
    /// - `master`: the session master from
    ///   [`derive_key`](crate::vault::CryptoVault::derive_key) — HKDF-expanded here
    ///   into the interleaver seed (never used as a raw AEAD/interleaver key).
    /// - `depth`: the block-interleaver depth `I` (codewords per window;
    ///   `1 ≤ depth ≤ `[`RS_INTERLEAVE_MAX`](crate::RS_INTERLEAVE_MAX)).
    ///
    /// # Returns
    /// A [`ConcatenatedFec`] whose interleaver is `BlockThenCsprng` seeded by
    /// `master`.
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if `depth` is out of range;
    /// [`CryptoError::KeyDerivation`] if HKDF seed expansion fails.
    pub fn with_csprng_from_master(master: &[u8], depth: usize) -> Result<Self> {
        let seed = crate::kdf::expand_interleaver_seed(master)?;
        let block = BlockInterleaver::new(depth)?;
        let csprng = CsprngLayer::new(&seed)?;
        Ok(Self::new(
            ReedSolomonCodec,
            Interleaver::BlockThenCsprng(block, csprng),
            ViterbiCodec,
        ))
    }
}

impl Default for ConcatenatedFec {
    /// Wires the audited default stack: RS(255,223), a depth-5 deterministic
    /// block interleaver (`DEFAULT_INTERLEAVE_DEPTH`), and the CCSDS Viterbi
    /// codec.
    fn default() -> Self {
        Self::new(
            ReedSolomonCodec,
            Interleaver::Block(
                // Statically valid: DEFAULT_INTERLEAVE_DEPTH is within
                // `1..=RS_INTERLEAVE_MAX` by construction.
                BlockInterleaver::new(DEFAULT_INTERLEAVE_DEPTH)
                    .expect("DEFAULT_INTERLEAVE_DEPTH is a valid interleave depth"),
            ),
            ViterbiCodec,
        )
    }
}

impl ErrorCorrection for ConcatenatedFec {
    /// Encodes `data` through the full pipeline `Viterbi(interleave(RS(data)))`
    /// (SR-F4).
    fn encode(&self, data: &[u8]) -> Vec<u8> {
        self.vt.encode(&self.il.interleave(&self.rs.encode(data)))
    }

    /// Decodes a received blob through the exact inverse pipeline, recovering the
    /// original `data` truncated to `pre_len` (SR-F4).
    ///
    /// Stages, in order: **(1)** structural pre-FEC validation
    /// (`validate_pre_fec`, SR-R3a) derives the
    /// expected RS-stream length `l` and rejects a malformed/oversized blob before
    /// any large allocation; **(2)** Viterbi decode; **(3)** a post-Viterbi
    /// length cross-check (`rs_stream.len() == l`, SR-R3b) that catches a
    /// codec-length bug; **(4)** de-interleave then Reed-Solomon decode.
    ///
    /// # Errors
    /// - [`crate::error::CryptoError::InvalidInput`] if the blob fails structural
    ///   validation (SR-R3a) or the post-Viterbi length is inconsistent (SR-R3b).
    /// - [`crate::error::CryptoError::ErrorCorrection`] if corruption exceeds the
    ///   concatenated code's correction capacity.
    fn decode(&self, encoded: &[u8], pre_len: usize) -> Result<Vec<u8>> {
        // (1) SR-R3a: structural pre-FEC gate → expected RS-stream length.
        let l = validate_pre_fec(encoded)?;
        // (2) Invert the inner Viterbi code.
        let rs_stream = self.vt.decode(encoded)?;
        // (3) SR-R3b: the actual decoded length must match the pre-derived `l`
        // (defends against a Viterbi-crate length bug).
        if rs_stream.len() != l {
            // SR-R7: generic, oracle-free message — the exact framed/decoded
            // lengths are structural detail withheld from a probing attacker.
            return Err(CryptoError::InvalidInput("malformed blob".into()));
        }
        // (4) Undo the interleaver, then the outer Reed-Solomon code.
        self.rs.decode(&self.il.deinterleave(&rs_stream), pre_len)
    }

    /// Validates the chunked-Viterbi framing and returns the recovered RS data
    /// length (SR-R3a / SR-R4).
    ///
    /// Delegates to the free `validate_pre_fec` (the single authoritative
    /// chunked-Viterbi structural check, shared with [`decode`](Self::decode)'s
    /// SR-R3b cross-check), then maps the derived RS-stream length `l` to the
    /// pre-decode data length `(l / RS_BLOCK) · RS_DATA` — the exact `pre_len`
    /// [`decode`](Self::decode) truncates to.
    fn validate_pre_fec(&self, received: &[u8]) -> Result<usize> {
        let l = validate_pre_fec(received)?;
        // `l` is a positive whole multiple of RS_BLOCK (guaranteed above), each
        // codeword carrying RS_DATA data bytes.
        Ok((l / RS_BLOCK) * RS_DATA)
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

    /// L12 / SR-F2: the ergonomic `ConcatenatedFec::with_csprng_from_master`
    /// constructor (optional CSPRNG obfuscation layer, HKDF-seeded from a master
    /// with vault-enforced domain separation) produces a working, reversible FEC
    /// that round-trips through a `CryptoVault::new(.., .., Box::new(fec))`; an
    /// out-of-range depth is rejected before any wiring.
    #[test]
    fn test_l12_csprng_from_master_fec_roundtrips_via_vault() {
        use crate::cipher::Aes256GcmSivCipher;
        use crate::error::CryptoError;
        use crate::kdf::Argon2Kdf;
        use crate::vault::CryptoVault;
        use crate::{KEY_LEN, SALT_LEN};

        // A master used to seed the interleaver (HKDF-derived internally).
        let seed_master = CryptoVault::default()
            .derive_key("interleaver-master", &[0u8; SALT_LEN])
            .unwrap();
        let fec = ConcatenatedFec::with_csprng_from_master(&seed_master, 5).unwrap();
        let vault = CryptoVault::new(
            Box::new(Argon2Kdf),
            Box::new(Aes256GcmSivCipher),
            Box::new(fec),
        );

        let key = [0x7Bu8; KEY_LEN];
        let blob = vault
            .encrypt_with_key(&key, "obfuscated over a noisy channel")
            .unwrap();
        let recovered = vault.decrypt_with_key(&key, &blob).unwrap();
        assert_eq!(&**recovered, "obfuscated over a noisy channel");

        // An out-of-range depth is rejected before any wiring.
        assert!(matches!(
            ConcatenatedFec::with_csprng_from_master(&seed_master, 0),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    /// L12 / M1-class: `with_csprng_from_master` validates the master length up
    /// front (HKDF silently accepts any-length IKM, so a wrong-length master would
    /// otherwise be expanded into a seed). An empty master is rejected with
    /// `InvalidInput`; a correct `KEY_LEN` master still succeeds.
    #[test]
    fn test_l12_csprng_from_master_rejects_wrong_length_master() {
        use crate::error::CryptoError;
        use crate::KEY_LEN;

        assert!(
            matches!(
                ConcatenatedFec::with_csprng_from_master(&[], 5),
                Err(CryptoError::InvalidInput(_))
            ),
            "an empty (wrong-length) master must be rejected with InvalidInput"
        );
        assert!(
            ConcatenatedFec::with_csprng_from_master(&[0u8; KEY_LEN], 5).is_ok(),
            "a correct KEY_LEN master must still succeed"
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
