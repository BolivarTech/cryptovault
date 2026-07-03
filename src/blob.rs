// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Blob format: wire encoding/decoding and structural validation performed
//! before any large allocation (implemented in Tasks 10-14, SR-R1/R3/R4/R6).

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
