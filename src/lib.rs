// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
#![forbid(unsafe_code)]
//! Authenticated encryption resilient over interference channels:
//! `VT(interleave(RS(AEAD(data))))`.
//!
//! `cryptovault` composes a by-the-book authenticated-encryption core with a
//! concatenated forward-error-correction (FEC) stack so that a ciphertext can
//! survive transport over a noisy / lossy channel and still either decrypt
//! correctly or fail loudly — never silently return wrong plaintext.
//!
//! ## Pipeline
//!
//! ```text
//! encrypt:  AEAD(data) -> RS -> interleave -> Viterbi -> base64 blob
//! decrypt:  base64 blob -> Viterbi -> deinterleave -> RS -> AEAD(data)
//! ```
//!
//! - **Security** (never rolled here — vetted RustCrypto only): Argon2id master
//!   key derivation, HKDF sub-key expansion, AES-256-GCM-SIV AEAD with the blob
//!   header bound as additional authenticated data (AAD).
//! - **Resilience** (not a security primitive): Reed-Solomon `RS(255,223)`,
//!   deterministic block interleaving (+ optional CSPRNG obfuscation), and a
//!   `K=7, R=1/2` Viterbi convolutional inner code.
//!
//! ## Format
//!
//! A single wire format, [`BLOB_VERSION`] `= 1` — clean-slate, no legacy and no
//! backward compatibility. The blob header lives **inside** the FEC envelope.
//! Framed delivery (splitting a stream into blobs) is the caller's job.
//!
//! See `sbtdd/spec-behavior.md` for the full specification.

pub mod blob;
pub mod cipher;
pub mod error;
pub mod fec;
pub mod kdf;
pub mod vault;

/// AES-256 key length (bytes).
pub const KEY_LEN: usize = 32;

/// Per-context Argon2 salt length (bytes).
pub const SALT_LEN: usize = 16;

/// AES-256-GCM-SIV nonce length (bytes).
pub const NONCE_LEN: usize = 12;

/// AEAD authentication tag length (bytes).
pub const TAG_LEN: usize = 16;

/// Upper bound on a single plaintext record (10 MiB, fixed — spec SR-R4/P0-5).
pub const MAX_PLAINTEXT_LEN: usize = 10 * 1024 * 1024;

/// Blob header length: `version (1)` + `plaintext_len (u32 LE, 4)`.
pub const HEADER_LEN: usize = 5;

/// Viterbi zero-tail overhead (`2L + 2` ⇒ `+2` bytes).
///
/// PROVISIONAL — confirmed by the Task 9 (P0-3) Viterbi trellis KAT against the
/// actual `viterbi` 0.0.1 crate. If the crate's real termination differs, this
/// constant is corrected there (and [`MAX_BLOB_LEN`] recomputes accordingly)
/// before the blob format is locked.
pub const TERMINATION_OVERHEAD: usize = 2;

/// On-disk blob format version (single concatenated format, no legacy).
pub const BLOB_VERSION: u8 = 1;

/// Reed-Solomon data bytes per codeword.
pub const RS_DATA: usize = 223;

/// Reed-Solomon parity bytes per codeword.
pub const RS_PARITY: usize = 32;

/// Reed-Solomon codeword length (`RS_DATA + RS_PARITY`).
pub const RS_BLOCK: usize = 255;

/// Maximum interleave depth `I` (codewords per interleaver window).
pub const RS_INTERLEAVE_MAX: usize = 16;

/// Reed-Solomon-stream bytes per Viterbi encode/decode sub-block.
///
/// The inner `viterbi` 0.0.1 codec caps a single block at
/// `MAX_SUPPORTED_INFO_BITS = 1_000_000` bits (`125_000` bytes). A full-payload
/// RS stream (up to ≈ 12 MiB at the 10 MiB plaintext cap) exceeds that, so the
/// Viterbi layer is applied in fixed sub-blocks of `VITERBI_CHUNK` bytes, each
/// contributing its own [`TERMINATION_OVERHEAD`] zero-tail.
///
/// Chosen as `490 × RS_BLOCK = 124_950` bytes so a chunk aligns to whole
/// Reed-Solomon codewords and its `124_950 × 8 = 999_600` info bits stay under
/// the crate cap. The receiver derives the chunk structure from the framed body
/// length alone (all chunks but the last encode exactly `VITERBI_CHUNK` bytes) —
/// no bootstrapping, consistent with the framed-delivery rule (SR-R2 / SR-F3).
pub const VITERBI_CHUNK: usize = 490 * RS_BLOCK;

/// Argon2id memory cost, KiB (OWASP 2025: 64 MiB).
pub const ARGON2_M_KIB: u32 = 65536;

/// Argon2id time cost / iterations (OWASP 2025).
pub const ARGON2_T: u32 = 3;

/// Argon2id parallelism lanes (OWASP 2025).
pub const ARGON2_P: u32 = 4;

/// Maximum FEC-encoded blob length — computed **analytically at compile time**
/// (real, non-zero) so the allocation-DoS guard is functional from Task 0.
///
/// Derivation: the protected payload (header ‖ nonce ‖ max ciphertext ‖ tag) is
/// Reed-Solomon expanded by `RS_BLOCK / RS_DATA`, then Viterbi expanded by `2×`
/// plus the zero-tail [`TERMINATION_OVERHEAD`].
pub const MAX_BLOB_LEN: usize = {
    let protected_max = MAX_PLAINTEXT_LEN + HEADER_LEN + NONCE_LEN + TAG_LEN;
    // Ceil-div written out (const-safe on MSRV 1.70; `div_ceil` is 1.73+).
    let rs_blocks = (protected_max + RS_DATA - 1) / RS_DATA;
    rs_blocks * RS_BLOCK * 2 + TERMINATION_OVERHEAD
};

/// Maximum accepted base64 input length — caps allocation **before** decode
/// (SR-R4 DoS guard). Base64 expands ~`4/3`; `+4` covers padding slack.
pub const MAX_B64_LEN: usize = MAX_BLOB_LEN * 4 / 3 + 4;

/// Recommended maximum plaintext per blob for good channel recovery
/// (BER-derived).
///
/// The FEC recovery guarantee is per-blob and all-or-nothing: past the
/// correction capacity a blob fails entirely. Callers should frame large data
/// into several small blobs rather than one big one.
///
/// PROVISIONAL (`128 KiB`) — derived from the Phase-4 preliminary bit-error-rate
/// pass (`tests/ber_provisional.rs`) over the **outer** FEC only (RS(255,223) +
/// block interleaver, no Viterbi yet). At a 0.2% binary-symmetric channel the
/// per-codeword failure probability is ≈9.7e-7, keeping blob recovery ≥99.9% up
/// to ≈223 KiB; `128 KiB` sits comfortably below that with margin for the
/// all-or-nothing cliff. Because the inner Viterbi code (Task 9) adds coding
/// gain, this is a **conservative lower bound**. Hidden from the public API and
/// finalized by the full Task 23b sweep (spec SR-F6). **Not user-facing yet.**
#[doc(hidden)]
pub const RECOMMENDED_MAX_PAYLOAD: usize = 128 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    // This is a constant-pinning regression test: asserting on compile-time
    // constants is the intent (guards the pinned wire-format values against
    // accidental edits), so `assertions_on_constants` is a false positive here.
    #[allow(clippy::assertions_on_constants)]
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
