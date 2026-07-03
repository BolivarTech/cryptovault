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
//! # Operational constraints (read before deploying)
//!
//! These are contracts the crate cannot enforce for you. Review each before
//! putting `cryptovault` on a real channel.
//!
//! ### All-or-nothing recovery — frame large data into small blobs
//!
//! FEC recovery is **all-or-nothing per blob**: if channel corruption exceeds the
//! concatenated code's correction capacity *anywhere* in a blob, the **entire**
//! blob fails to decrypt — there is **no partial recovery**, because the AEAD
//! needs the complete ciphertext to verify its tag. Larger blobs are
//! correspondingly more fragile (more bytes, more chances to exceed capacity).
//!
//! Keep each plaintext at or below [`RECOMMENDED_MAX_PAYLOAD`] (`128 KiB`, the
//! BER-derived practical ceiling — see `docs/ber-analysis.md`). The absolute cap
//! is [`MAX_PLAINTEXT_LEN`] (10 MiB), but blobs approaching it survive channel
//! noise far less reliably. **Frame large data into multiple
//! `RECOMMENDED_MAX_PAYLOAD`-sized blobs**: each frame then fails or recovers
//! independently, so one bad frame does not doom the rest.
//!
//! ### Concurrency — bound your concurrent decrypts
//!
//! Decryption is memory-heavy: a single decrypt holds several O(blob)-sized
//! buffers at once and **peaks at ≈ 80 MB per blob** at the 10 MiB cap. The vault
//! is `Send + Sync` and has **no built-in concurrency limit**, so `N` concurrent
//! decrypts consume ≈ `N × 80 MB`. **Callers MUST bound concurrent decrypts**
//! (a semaphore or worker pool) or risk out-of-memory — concurrency policy is
//! deliberately a caller/service-layer concern.
//!
//! ### Nonce birthday bound — rekey long-lived keys
//!
//! Each record draws a fresh 12-byte `OsRng` nonce. The birthday bound is
//! ≈ **2⁴⁸ records per key**; GCM-SIV's misuse resistance means a collision only
//! leaks plaintext *equality* (never the key or plaintext), but you SHOULD
//! **rekey before encrypting > 2⁴⁸ records under one key**.
//!
//! ### Salt uniqueness is your contract
//!
//! The per-context Argon2 salt is **caller-managed and out-of-band** (never in the
//! blob). Obtain every salt from [`vault::generate_salt`] (never hand-rolled) and
//! use a **distinct salt per context**: reusing a salt yields the same master key
//! across contexts (a key collision). The stateless crate cannot detect reuse.
//!
//! ### `derive_key` is memory-hard — rate-limit untrusted callers
//!
//! [`vault::CryptoVault::derive_key`] runs **memory-hard Argon2id (64 MiB of RAM
//! plus CPU, per call)** and is intended to run **once per session** (SR-C2). It
//! is therefore a resource-exhaustion / DoS surface: a service exposing
//! `derive_key` to untrusted callers **MUST rate-limit it**, since each call
//! costs 64 MiB + CPU and unbounded invocation can exhaust memory/CPU. The
//! per-record encrypt/decrypt and envelope paths use the **cached** master and do
//! **not** re-run Argon2, so only `derive_key` carries the memory-hard cost.
//!
//! ### DC-1 — active-adversary FEC-availability limitation (optional layer only)
//!
//! The **default** deterministic block interleaver is public and keyless — no
//! permutation oracle exists, so this limitation **does not apply**. It applies
//! *only* when the **optional CSPRNG obfuscation layer** is enabled: that
//! permutation is static per key (the nonce lives inside the FEC body, so
//! per-record variation is impossible). An active adversary with an encryption
//! oracle could learn it and craft bursts to degrade **FEC resilience
//! (availability) only** — it **never** affects AEAD confidentiality or integrity.
//! The interleaver is obfuscation, not security.
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
/// Validated: the `2L + 2` per-chunk relation is confirmed by the Task 9 (P0-3)
/// Viterbi termination KAT (`test_p0_3_viterbi_termination_length_and_roundtrip`)
/// against the actual `viterbi` 0.0.1 crate, so the blob format and the derived
/// [`MAX_BLOB_LEN`] rest on a verified, locked formula.
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
/// Reed-Solomon expanded by `RS_BLOCK / RS_DATA`, then the Viterbi inner code
/// doubles the stream and appends **one [`TERMINATION_OVERHEAD`] zero-tail per
/// [`VITERBI_CHUNK`] sub-block** (the `viterbi` 0.0.1 block cap forces chunking —
/// P0-3 / P0-5): `rs_max·2 + TERMINATION_OVERHEAD·ceil(rs_max / VITERBI_CHUNK)`.
pub const MAX_BLOB_LEN: usize = {
    let protected_max = MAX_PLAINTEXT_LEN + HEADER_LEN + NONCE_LEN + TAG_LEN;
    // Ceil-div written out (const-safe on MSRV 1.70; `div_ceil` is 1.73+).
    let rs_blocks = (protected_max + RS_DATA - 1) / RS_DATA;
    let rs_max = rs_blocks * RS_BLOCK;
    let viterbi_chunks = (rs_max + VITERBI_CHUNK - 1) / VITERBI_CHUNK;
    rs_max * 2 + TERMINATION_OVERHEAD * viterbi_chunks
};

/// Maximum accepted base64 input length — caps allocation **before** decode
/// (SR-R4 DoS guard). Base64 expands ~`4/3`; `+4` covers padding slack.
pub const MAX_B64_LEN: usize = MAX_BLOB_LEN * 4 / 3 + 4;

/// Recommended maximum plaintext per blob for reliable channel recovery
/// (`128 KiB`, BER-derived).
///
/// FEC recovery is **all-or-nothing per blob**: if channel corruption exceeds the
/// concatenated code's capacity *anywhere* in the blob, the whole blob fails to
/// decrypt (the AEAD needs the complete ciphertext — there is no partial
/// recovery). This cliff is **per-blob**, so callers SHOULD frame large data into
/// several blobs at or below this size rather than one large blob: each frame
/// then fails or recovers independently, and one bad frame does not doom the rest.
///
/// **Validated (no longer provisional).** Derived from the full concatenated-FEC
/// availability analysis in `tests/ber_analysis.rs` (spec SR-F6) — the *complete*
/// `Viterbi(interleave(RS(·)))` pipeline over a deterministic-seed binary-
/// symmetric channel, summarized in `docs/ber-analysis.md`. The measured
/// per-codeword post-FEC failure probability is effectively **0 for channel bit-
/// error rates up to ≈5%**, with a sharp recovery waterfall near **≈6%** and total
/// loss by **≈10%**. At the documented operating point of **0.5% BSC** a blob
/// recovers with probability ≈1.0 up to the 10 MiB plaintext cap; `128 KiB` is a
/// deliberately **conservative** ceiling that keeps blob-level recovery ≥99.9%
/// with wide margin against the waterfall and against real-channel bursts the
/// memoryless BSC model understates.
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
        // Finalized BER-derived value (Task 23b / SR-F6); pinned so a change is a
        // deliberate, reviewed edit. See `docs/ber-analysis.md`.
        assert_eq!(RECOMMENDED_MAX_PAYLOAD, 128 * 1024);
        assert!(RECOMMENDED_MAX_PAYLOAD < MAX_PLAINTEXT_LEN);
    }
}
