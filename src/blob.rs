// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Blob format: wire encoding/decoding and structural validation performed
//! before any large allocation (implemented in Tasks 10-14, SR-R1/R3/R4/R6).

use crate::error::Result;

/// Structural pre-FEC validation gate (SR-R3a / SR-R4 / P0-6) — Red-phase stub.
///
/// Implemented in the Green phase; this stub exists only so the failing tests
/// compile and fail by assertion (no structural validation yet).
pub fn validate_pre_fec(_received: &[u8]) -> Result<usize> {
    Ok(0)
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
mod boundary_tests {
    use crate::fec::rs::ReedSolomonCodec;
    use crate::fec::viterbi::ViterbiCodec;
    use crate::fec::ErrorCorrection;
    use crate::{
        HEADER_LEN, MAX_B64_LEN, MAX_BLOB_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN, RS_BLOCK, RS_DATA,
        TAG_LEN, TERMINATION_OVERHEAD, VITERBI_CHUNK,
    };

    /// Ceil-div `a / b` (manual — MSRV 1.70, `div_ceil` is 1.73+).
    fn ceil_div(a: usize, b: usize) -> usize {
        (a + b - 1) / b
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
