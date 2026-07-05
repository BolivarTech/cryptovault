// Author: Julian Bolivar
// Version: 0.2.2
// Date: 2026-07-03
//! Blob format: wire encoding/decoding and structural validation performed
//! before any large allocation (implemented in Tasks 10-14, SR-R1/R3/R4/R6).

use crate::error::{CryptoError, Result};
use crate::fec::viterbi::rs_len_from_body;
use crate::fec::ErrorCorrection;
use crate::{
    BLOB_VERSION, HEADER_LEN, MAX_BLOB_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN, RS_BLOCK, TAG_LEN,
};

/// FEC-encodes a blob: `Viterbi(interleave(RS(version ‖ plaintext_len ‖ body)))`
/// (SR-R1 / SR-F4).
///
/// The header (`version` + little-endian `plaintext_len`) is prepended to `body`
/// and the whole `protected` payload is run through the injected FEC stack, so
/// **every byte, header included, is FEC-protected**. The header is *also* bound
/// as AAD by the caller ([`crate::vault`]) — recoverable *and* tamper-evident.
///
/// # Parameters
/// - `fec`: the error-correction stack to encode through (the audited default is
///   [`crate::fec::ConcatenatedFec`]).
/// - `version`: the blob format version (normally [`crate::BLOB_VERSION`]).
/// - `plaintext_len`: the original plaintext length in bytes — a **header field**
///   distinct from the RS truncation length `protected_len` (no collision).
/// - `body`: the AEAD output `nonce ‖ ciphertext ‖ tag`.
///
/// # Returns
/// The FEC-encoded blob bytes (base64 is applied one layer up, in the vault).
///
/// # Examples
///
/// Crate-internal (the `blob` module is `pub(crate)`, L4), so this is an
/// illustration rather than a compiled doctest; the round-trip is exercised by
/// the `blob_codec_tests` unit tests below.
///
/// ```ignore
/// use crate::blob::{decode_blob, encode_blob};
/// use crate::fec::ConcatenatedFec;
/// use crate::BLOB_VERSION;
///
/// let fec = ConcatenatedFec::default();
/// let body = vec![9u8; 40];
/// let blob = encode_blob(&fec, BLOB_VERSION, 12, &body);
/// let (v, pl, recovered) = decode_blob(&fec, &blob).unwrap();
/// assert_eq!((v, pl, recovered), (BLOB_VERSION, 12, body));
/// ```
pub fn encode_blob(
    fec: &dyn ErrorCorrection,
    version: u8,
    plaintext_len: u32,
    body: &[u8],
) -> Vec<u8> {
    // protected = version(1B) ‖ plaintext_len(u32 LE, 4B) ‖ body.
    let mut protected = Vec::with_capacity(HEADER_LEN + body.len());
    protected.push(version);
    protected.extend_from_slice(&plaintext_len.to_le_bytes());
    protected.extend_from_slice(body);
    fec.encode(&protected)
}

/// FEC-decodes a received blob and recovers its header and body (SR-R1 / SR-R3 /
/// SR-R6).
///
/// The **safety-critical ordering** (SR-R6) is: structural pre-FEC validation →
/// FEC-correct → read the error-corrected header → validate it → slice the body.
/// The `version` and `plaintext_len` are recovered *from inside* the FEC (never
/// from an unprotected prefix), so a channel-corrupted header is error-corrected
/// rather than fatal, and the recovered header is what the caller binds as AAD.
///
/// Steps:
/// 1. [`ErrorCorrection::validate_pre_fec`] — the **strategy-owned** structural
///    gate — derives the pre-decode payload length and rejects an
///    oversized/malformed blob before any large allocation (SR-R3a / SR-R4).
///    Delegating to the injected strategy keeps this function format-agnostic:
///    the concatenated FEC derives the length from its chunked-Viterbi framing,
///    while [`crate::vault::NoFec`] returns the raw blob length (SR-R2, no
///    bootstrapping — the length comes from the framed blob, not the header).
/// 2. `fec.decode(received, recovered_len)` recovers the protected payload.
/// 3. Read the error-corrected header at offset 0; validate
///    `version == BLOB_VERSION`, `plaintext_len ≤ MAX_PLAINTEXT_LEN`, and the
///    derived `protected_len ≤ recovered_len` (header offsets in bounds).
/// 4. Return `(version, plaintext_len, body)` where `body = protected[HEADER_LEN
///    .. protected_len]` (`nonce ‖ ciphertext ‖ tag`).
///
/// # Parameters
/// - `fec`: the error-correction stack (must match the encode side).
/// - `received`: the raw received blob (post-base64-decode).
///
/// # Returns
/// `(version, plaintext_len, body)` — the recovered header fields and the AEAD
/// body.
///
/// # Errors
/// [`CryptoError::InvalidInput`] on any structural violation (oversized, bad
/// framing, unknown version, oversized `plaintext_len`, or a `protected_len`
/// past the recovered payload); [`CryptoError::ErrorCorrection`] if corruption
/// exceeds the FEC capacity. **Never panics** on adversarial input (SC-6 /
/// SR-R5).
pub fn decode_blob(fec: &dyn ErrorCorrection, received: &[u8]) -> Result<(u8, u32, Vec<u8>)> {
    // (1) SR-R3a / SR-R4: strategy-owned structural gate → pre-decode payload
    // length. The concatenated FEC derives it from the chunked-Viterbi framing;
    // NoFec returns the raw blob length. Delegating keeps decode_blob
    // format-agnostic so an injected strategy can decode its own output.
    let recovered_len = fec.validate_pre_fec(received)?;
    // (2) FEC-correct the whole payload, truncated to the recovered length (a
    // no-op for the RS path, which already yields exactly this many data bytes).
    let protected = fec.decode(received, recovered_len)?;
    // (3) Read the error-corrected header @0. `recovered_len >= RS_DATA (223)`
    // by construction for the RS path, but guard defensively so a codec length
    // bug cannot panic.
    // SR-R7: all decode-path rejections use fixed, generic messages — no
    // recovered length, offset, or version value is echoed to a probing attacker.
    if protected.len() < HEADER_LEN {
        return Err(CryptoError::InvalidInput("malformed blob".into()));
    }
    let version = protected[0];
    if version != BLOB_VERSION {
        return Err(CryptoError::InvalidInput("unsupported blob version".into()));
    }
    // Length-checked above, so this fixed-size conversion cannot panic.
    let plaintext_len = u32::from_le_bytes(
        protected[1..HEADER_LEN]
            .try_into()
            .expect("HEADER_LEN - 1 == 4 bytes, statically a valid u32"),
    );
    if plaintext_len as usize > MAX_PLAINTEXT_LEN {
        return Err(CryptoError::InvalidInput("malformed blob".into()));
    }
    // `protected_len` (RS truncation length) is derived from the header — a name
    // distinct from `plaintext_len` (the header field). No overflow:
    // plaintext_len ≤ MAX_PLAINTEXT_LEN so the sum is far below usize::MAX.
    let protected_len = HEADER_LEN + NONCE_LEN + plaintext_len as usize + TAG_LEN;
    if protected_len > protected.len() {
        return Err(CryptoError::InvalidInput("malformed blob".into()));
    }
    // (4) Slice out body = nonce ‖ ciphertext ‖ tag (padding beyond protected_len
    // is discarded).
    let body = protected[HEADER_LEN..protected_len].to_vec();
    Ok((version, plaintext_len, body))
}

/// Validates a received FEC body's framing **before** any FEC decode and returns
/// the derived Reed-Solomon stream length `L` (SR-R3a / SR-R4 / P0-6).
///
/// This is the first, cheap, allocation-free gate on the decrypt path: it never
/// touches the FEC codecs, so a hostile or malformed blob is rejected before it
/// can drive a large allocation or reach the early-stage FEC crates. The checks,
/// in order:
///
/// 1. **DoS cap (SR-R4):** `received.len() ≤ `[`MAX_BLOB_LEN`].
/// 2. **Chunked-Viterbi consistency (SR-R3a):** `received.len()` inverts through
///    the *same* chunk math the decoder uses (`rs_len_from_body` — the single
///    source of truth), so TX and RX agree byte-for-byte; a body inconsistent
///    with the per-chunk coded formula is rejected here.
/// 3. **RS framing (SR-R3a):** the derived `L` is a **positive whole multiple**
///    of [`RS_BLOCK`] (at least one codeword).
///
/// # Parameters
/// - `received`: the raw received FEC body (the Viterbi-encoded stream, before
///   base64 is stripped at the blob layer).
///
/// # Returns
/// The derived RS-stream length `L` in bytes, to be cross-checked against the
/// actual post-Viterbi length (SR-R3b, in the FEC decode).
///
/// # Errors
/// [`CryptoError::InvalidInput`] on any violation above. **Never panics** on
/// adversarial input (SC-6 / SR-R5).
///
/// # Examples
///
/// Crate-internal (the `blob` module is `pub(crate)`, L4), so this is an
/// illustration rather than a compiled doctest; the behavior is exercised by the
/// `validation_tests` unit tests below.
///
/// ```ignore
/// use crate::blob::validate_pre_fec;
/// use crate::fec::ViterbiCodec;
/// use crate::RS_BLOCK;
///
/// // A Viterbi body encoding one RS codeword validates to L = RS_BLOCK.
/// let body = ViterbiCodec.encode(&vec![0u8; RS_BLOCK]);
/// assert_eq!(validate_pre_fec(&body).unwrap(), RS_BLOCK);
///
/// // Junk is rejected, never a panic.
/// assert!(validate_pre_fec(&[0u8; 3]).is_err());
/// ```
pub fn validate_pre_fec(received: &[u8]) -> Result<usize> {
    // (1) SR-R4: reject an over-cap blob before any FEC allocation. SR-R7: a
    // length cap is not an oracle, but avoid echoing the exact received length.
    if received.len() > MAX_BLOB_LEN {
        return Err(CryptoError::InvalidInput(
            "input exceeds maximum size".into(),
        ));
    }
    // (2) SR-R3a: derive L via the shared chunked-Viterbi math (validates the
    // per-chunk coded structure: even, minimum-size final sub-block).
    let l = rs_len_from_body(received.len())?;
    // (3) SR-R3a: the RS stream must be a positive whole number of codewords.
    // SR-R7: generic, oracle-free message — no derived length is echoed back.
    if l == 0 || l % RS_BLOCK != 0 {
        return Err(CryptoError::InvalidInput("malformed blob".into()));
    }
    Ok(l)
}

#[cfg(test)]
mod validation_tests {
    use super::validate_pre_fec;
    use crate::error::CryptoError;
    use crate::fec::viterbi::ViterbiCodec;
    use crate::{MAX_BLOB_LEN, RS_BLOCK};

    /// SR-R3a: a structurally valid FEC body (the Viterbi encoding of a whole
    /// number of RS codewords) validates and returns the exact derived RS-stream
    /// length `L`.
    #[test]
    fn test_sr_r3_valid_body_returns_derived_rs_stream_length() {
        let vt = ViterbiCodec;
        for codewords in [1usize, 2, 5] {
            let l = codewords * RS_BLOCK;
            let body = vt.encode(&vec![0u8; l]);
            assert_eq!(
                validate_pre_fec(&body).unwrap(),
                l,
                "derived L matches the encoded RS-stream length ({codewords} codewords)"
            );
        }
    }

    /// SR-R4: a body longer than `MAX_BLOB_LEN` is rejected before any FEC
    /// allocation.
    #[test]
    fn test_sr_r4_oversized_body_is_invalid_input() {
        let oversized = vec![0u8; MAX_BLOB_LEN + 1];
        assert!(matches!(
            validate_pre_fec(&oversized),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    /// SR-R3a: a body whose derived RS-stream length is not a whole multiple of
    /// `RS_BLOCK` (here `L = 100`, structurally consistent as a Viterbi body but
    /// not a valid RS stream) is rejected.
    #[test]
    fn test_sr_r3_non_rs_block_multiple_is_invalid_input() {
        // 100 info bytes → coded body 2·100 + 2 = 202 bytes; 100 is not a
        // multiple of RS_BLOCK.
        let body = vec![0u8; 202];
        assert!(matches!(
            validate_pre_fec(&body),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    /// SR-R3a: a body length inconsistent with the per-chunk coded formula (odd,
    /// so it cannot be `2·il + 2`) is rejected, never a panic.
    #[test]
    fn test_sr_r3_odd_body_length_is_invalid_input() {
        let body = vec![0u8; 205]; // odd → not a valid coded body
        assert!(matches!(
            validate_pre_fec(&body),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    /// SR-R3a: bodies too short to hold even one codeword — empty and below the
    /// minimum chunk body — are rejected.
    #[test]
    fn test_sr_r3_too_short_body_is_invalid_input() {
        assert!(matches!(
            validate_pre_fec(&[]),
            Err(CryptoError::InvalidInput(_))
        ));
        assert!(matches!(
            validate_pre_fec(&[0u8; 2]),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    /// SC-6 / SR-R5: `validate_pre_fec` never panics on arbitrary bytes — every
    /// input yields either a derived length or a typed `InvalidInput`.
    #[test]
    fn test_sc6_validate_pre_fec_never_panics_on_junk() {
        for len in [1usize, 3, 4, 254, 256, 511, 513, 1021, 1023] {
            let junk: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            // Must not panic; result is either Ok(L) or a typed error.
            let _ = validate_pre_fec(&junk);
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::validate_pre_fec;
    use proptest::prelude::*;

    proptest! {
        /// SC-6 / SR-R5: over thousands of arbitrary byte strings,
        /// `validate_pre_fec` never panics — the decrypt-path structural guard is
        /// total.
        #[test]
        fn prop_sr_r5_validate_pre_fec_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = validate_pre_fec(&bytes);
        }
    }
}

#[cfg(test)]
mod blob_codec_tests {
    use super::{decode_blob, encode_blob};
    use crate::error::CryptoError;
    use crate::fec::ConcatenatedFec;
    use crate::{BLOB_VERSION, MAX_PLAINTEXT_LEN, NONCE_LEN, TAG_LEN};

    /// SR-R1 / SR-R6: a blob round-trips the header (`version` + `plaintext_len`)
    /// and body from *inside* the FEC envelope — the header is recovered
    /// error-corrected, not read from any unprotected prefix. The body length is
    /// `NONCE_LEN + plaintext_len + TAG_LEN` (the real `nonce ‖ ct ‖ tag` shape),
    /// and `decode_blob` strips any RS zero-padding back to exactly that.
    #[test]
    fn test_sr_r6_encode_decode_blob_roundtrips_header_from_inside_fec() {
        let fec = ConcatenatedFec::default();
        let plaintext_len = 261u32; // header field, distinct from the RS length.
                                    // body = nonce ‖ ciphertext(plaintext_len) ‖ tag.
        let body: Vec<u8> = (0..(NONCE_LEN + plaintext_len as usize + TAG_LEN))
            .map(|i| (i * 7 + 1) as u8)
            .collect();
        let blob = encode_blob(&fec, BLOB_VERSION, plaintext_len, &body);
        let (v, pl, recovered_body) = decode_blob(&fec, &blob).unwrap();
        assert_eq!(v, BLOB_VERSION, "version recovered from inside the FEC");
        assert_eq!(pl, plaintext_len, "plaintext_len recovered from the header");
        assert_eq!(
            recovered_body, body,
            "body recovered exactly (padding stripped)"
        );
    }

    /// SR-R1: an unknown blob version (recovered from inside the FEC) is rejected
    /// as a typed error — never mis-parsed as the current format.
    #[test]
    fn test_sr_r1_decode_blob_rejects_unknown_version() {
        let fec = ConcatenatedFec::default();
        let body: Vec<u8> = (0..40u32).map(|i| i as u8).collect();
        // Encode under an unsupported version byte.
        let blob = encode_blob(&fec, 2, 40, &body);
        assert!(
            matches!(decode_blob(&fec, &blob), Err(CryptoError::InvalidInput(_))),
            "version != BLOB_VERSION must be rejected"
        );
    }

    /// SR-R6: a header whose `plaintext_len` exceeds `MAX_PLAINTEXT_LEN` is
    /// rejected before any truncation, never over-allocated.
    #[test]
    fn test_sr_r6_decode_blob_rejects_oversized_plaintext_len() {
        let fec = ConcatenatedFec::default();
        let body: Vec<u8> = (0..40u32).map(|i| i as u8).collect();
        let oversized = (MAX_PLAINTEXT_LEN + 1) as u32;
        let blob = encode_blob(&fec, BLOB_VERSION, oversized, &body);
        assert!(
            matches!(decode_blob(&fec, &blob), Err(CryptoError::InvalidInput(_))),
            "plaintext_len > MAX_PLAINTEXT_LEN must be rejected"
        );
    }

    /// SR-R6: a `plaintext_len` larger than the recovered payload (so the derived
    /// `protected_len` runs past the recovered bytes) is rejected as structurally
    /// invalid, never a slice panic.
    #[test]
    fn test_sr_r6_decode_blob_rejects_protected_len_past_recovered() {
        let fec = ConcatenatedFec::default();
        let body: Vec<u8> = (0..40u32).map(|i| i as u8).collect();
        // Plausible plaintext_len (< cap) but far larger than the tiny body →
        // protected_len > recovered_len.
        let blob = encode_blob(&fec, BLOB_VERSION, 100_000, &body);
        assert!(
            matches!(decode_blob(&fec, &blob), Err(CryptoError::InvalidInput(_))),
            "protected_len past recovered payload must be rejected"
        );
    }

    /// SR-R1 / SC-8: the empty-plaintext degenerate case (`plaintext_len = 0`,
    /// so the body is just `nonce ‖ tag` = 28 bytes) round-trips through the blob
    /// codec — there is always ≥ 1 RS codeword.
    #[test]
    fn test_sr_r1_empty_plaintext_roundtrips() {
        let fec = ConcatenatedFec::default();
        let body: Vec<u8> = (0..(NONCE_LEN + TAG_LEN)).map(|i| i as u8).collect();
        let blob = encode_blob(&fec, BLOB_VERSION, 0, &body);
        let (v, pl, recovered) = decode_blob(&fec, &blob).unwrap();
        assert_eq!(v, BLOB_VERSION);
        assert_eq!(pl, 0);
        assert_eq!(recovered, body, "nonce ‖ tag body round-trips");
    }

    /// SC-6 / SR-R5: `decode_blob` never panics on adversarial bytes — a junk
    /// buffer yields a typed error, never a crash.
    #[test]
    fn test_sc6_decode_blob_never_panics_on_junk() {
        let fec = ConcatenatedFec::default();
        for len in [0usize, 1, 3, 4, 202, 512] {
            let junk: Vec<u8> = (0..len).map(|i| (i * 13 + 5) as u8).collect();
            let _ = decode_blob(&fec, &junk); // must return, never panic
        }
    }
}

#[cfg(test)]
mod boundary_tests {
    use crate::fec::rs::ReedSolomonCodec;
    use crate::fec::viterbi::ViterbiCodec;
    use crate::fec::ErrorCorrection;
    use crate::{
        HEADER_LEN, MAX_B64_LEN, MAX_BLOB_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN, RS_BLOCK, RS_DATA,
        TAG_LEN, TERMINATION_OVERHEAD, VITERBI_CHUNK,
    };

    /// Ceil-div `a / b` (manual const-safe form; `div_ceil` is not `const fn`).
    fn ceil_div(a: usize, b: usize) -> usize {
        a.div_ceil(b)
    }

    /// Task 10 / SR-F1: the Reed-Solomon layer transition lands on whole codewords
    /// exactly at the 223-byte chunk boundaries — `223→1`, `224→2`, `446→2`,
    /// `447→3` codewords — so a payload straddling a chunk edge expands as the
    /// format pins, and every boundary payload round-trips.
    #[test]
    fn test_sr_f1_rs_chunk_boundary_codeword_counts_and_roundtrip() {
        let rs = ReedSolomonCodec;
        for (payload_len, expected_blocks) in [
            (RS_DATA, 1),
            (RS_DATA + 1, 2),
            (2 * RS_DATA, 2),
            (2 * RS_DATA + 1, 3),
        ] {
            let data = vec![0xA5u8; payload_len];
            let enc = rs.encode(&data);
            assert_eq!(
                enc.len(),
                expected_blocks * RS_BLOCK,
                "payload {payload_len} → {expected_blocks} codewords"
            );
            assert_eq!(
                rs.decode(&enc, payload_len).unwrap(),
                data,
                "boundary payload {payload_len} round-trips"
            );
        }
    }

    /// Task 10 / P0-3: a Reed-Solomon stream of exactly `VITERBI_CHUNK` bytes is
    /// the largest single Viterbi sub-block — exactly one zero-tail,
    /// `2·VITERBI_CHUNK + TERMINATION_OVERHEAD` coded bytes — pinning the
    /// chunk-boundary transition (one codeword more rolls to a second sub-block,
    /// covered by the Viterbi multi-chunk test).
    #[test]
    fn test_p0_3_viterbi_exact_chunk_boundary_single_tail() {
        let v = ViterbiCodec;
        let one = vec![0x33u8; VITERBI_CHUNK];
        let enc = v.encode(&one);
        assert_eq!(
            enc.len(),
            2 * VITERBI_CHUNK + TERMINATION_OVERHEAD,
            "exact-boundary chunk is one sub-block with one tail"
        );
        assert_eq!(
            v.decode(&enc).unwrap(),
            one,
            "exact-boundary chunk round-trips"
        );
    }

    /// Task 10 / P0-5: `MAX_BLOB_LEN` recomputes from the pinned per-chunk formula
    /// `rs_max·2 + TERMINATION_OVERHEAD·ceil(rs_max / VITERBI_CHUNK)`, `MAX_B64_LEN`
    /// tracks it (`·4/3 + 4`), and both strictly exceed the plaintext cap so the
    /// DoS guard admits a full-size blob (`MAX_BLOB_LEN ± 1` reasoning: a blob at
    /// the cap is accepted, one byte over is rejected by `validate_pre_fec`).
    // Constant-pinning regression: asserting on compile-time constants is the
    // intent, so `assertions_on_constants` is a false positive here.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_p0_5_max_blob_len_and_b64_len_recompute_from_formula() {
        let protected_max = MAX_PLAINTEXT_LEN + HEADER_LEN + NONCE_LEN + TAG_LEN;
        let rs_max = ceil_div(protected_max, RS_DATA) * RS_BLOCK;
        let viterbi_chunks = ceil_div(rs_max, VITERBI_CHUNK);
        assert_eq!(
            MAX_BLOB_LEN,
            rs_max * 2 + TERMINATION_OVERHEAD * viterbi_chunks,
            "MAX_BLOB_LEN uses the per-chunk Viterbi tail"
        );
        assert_eq!(
            MAX_B64_LEN,
            MAX_BLOB_LEN * 4 / 3 + 4,
            "MAX_B64_LEN caps the base64 input before decode"
        );
        assert!(MAX_BLOB_LEN > MAX_PLAINTEXT_LEN);
    }
}

#[cfg(test)]
mod full_path_crafted_tests {
    //! Full decrypt-path coverage for hostile blobs crafted at the wire layer.
    //!
    //! Migrated from `tests/scenarios.rs` (SC-4) and `tests/adversarial.rs` (L4):
    //! `encode_blob`/`decode_blob` are now `pub(crate)`, so a crafted-blob attack
    //! that must be driven through the **public** [`crate::vault::CryptoVault`]
    //! door lives here as a unit test — it needs both the crate-private blob
    //! crafting and the public API, which no integration test can combine anymore.

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    use super::{decode_blob, encode_blob};
    use crate::error::CryptoError;
    use crate::fec::ConcatenatedFec;
    use crate::vault::CryptoVault;
    use crate::{BLOB_VERSION, MAX_PLAINTEXT_LEN, NONCE_LEN, TAG_LEN};

    /// A fixed raw 32-byte master/KEK — the hostility is entirely in the crafted
    /// ciphertext, never the key.
    const MASTER: [u8; 32] = [0x5Au8; 32];
    /// A fixed per-context salt bound as AAD by `wrap_key`/`unwrap_key`.
    const SALT: [u8; 16] = [0xA5u8; 16];

    /// SC-4 (SR-C4, SR-R6): a blob whose error-corrected header (`plaintext_len`
    /// or `version`) is altered fails the AEAD tag / structural check through the
    /// public door — never wrong plaintext. The header is bound as AAD, so an
    /// altered-but-error-corrected header cannot authenticate.
    #[test]
    fn test_sc_4_tampered_header_fails_authentication() {
        let v = CryptoVault::default();
        let fec = ConcatenatedFec::default();
        let pt: Vec<u8> = (0..48u8).collect();

        // Recover the genuine (version, plaintext_len, body) of a real blob.
        let blob = v.wrap_key(&MASTER, &SALT, &pt).unwrap();
        let raw = STANDARD.decode(&blob).unwrap();
        let (version, plaintext_len, body) = decode_blob(&fec, &raw).unwrap();
        assert_eq!(version, BLOB_VERSION);
        assert_eq!(plaintext_len as usize, pt.len());

        // (a) Tamper `plaintext_len` (still ≤ body capacity): the recovered header
        // no longer matches the AAD the ciphertext was sealed under → Cipher error.
        let tampered_len = encode_blob(&fec, BLOB_VERSION, plaintext_len - 1, &body);
        let b64_len = STANDARD.encode(&tampered_len);
        assert!(
            matches!(
                v.unwrap_key(&MASTER, &SALT, &b64_len),
                Err(CryptoError::Cipher(_))
            ),
            "tampered plaintext_len must fail the AEAD tag"
        );

        // (b) Tamper `version`: decode rejects an unknown version before AEAD-open.
        let tampered_ver = encode_blob(&fec, BLOB_VERSION + 1, plaintext_len, &body);
        let b64_ver = STANDARD.encode(&tampered_ver);
        assert!(
            matches!(
                v.unwrap_key(&MASTER, &SALT, &b64_ver),
                Err(CryptoError::InvalidInput(_))
            ),
            "tampered version must be rejected as InvalidInput"
        );
    }

    /// Base64-encodes a FEC-valid blob built with an arbitrary `version` and
    /// `plaintext_len` header, so the corpus can probe the post-FEC header checks
    /// (bad version, oversized `plaintext_len`) through the public door.
    fn crafted_blob_b64(version: u8, plaintext_len: u32, body_len: usize) -> String {
        let fec = ConcatenatedFec::default();
        let body: Vec<u8> = (0..body_len).map(|i| (i * 7 + 1) as u8).collect();
        STANDARD.encode(encode_blob(&fec, version, plaintext_len, &body))
    }

    /// SR-R1 / SR-R6 (adversarial corpus): a structurally-valid FEC frame carrying
    /// an unsupported `version` byte, and one whose header `plaintext_len` exceeds
    /// `MAX_PLAINTEXT_LEN`, are each rejected with a typed `InvalidInput` through
    /// the public `unwrap_key` door — recovered error-corrected from inside the
    /// FEC, then rejected before AEAD-open, never a panic.
    #[test]
    fn test_sr_r6_crafted_bad_version_and_oversized_len_are_invalid_input() {
        let v = CryptoVault::default();

        let bad_version = crafted_blob_b64(2, 0, NONCE_LEN + TAG_LEN);
        assert!(
            matches!(
                v.unwrap_key(&MASTER, &SALT, &bad_version),
                Err(CryptoError::InvalidInput(_))
            ),
            "unsupported version byte must be rejected as InvalidInput"
        );

        let over_cap = crafted_blob_b64(1, (MAX_PLAINTEXT_LEN + 1) as u32, NONCE_LEN + TAG_LEN);
        assert!(
            matches!(
                v.unwrap_key(&MASTER, &SALT, &over_cap),
                Err(CryptoError::InvalidInput(_))
            ),
            "plaintext_len over the cap must be rejected as InvalidInput"
        );
    }
}
