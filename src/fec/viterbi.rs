// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Viterbi inner FEC: the [`ViterbiCodec`] wrapper over the author's own
//! `viterbi` 0.0.1 crate — CCSDS `K=7, R=1/2` hard-decision convolutional code
//! (SR-F3 / P0-3).

use crate::error::Result;

/// CCSDS `K=7, R=1/2` hard-decision Viterbi inner code (SR-F3 / P0-3).
pub struct ViterbiCodec;

impl ViterbiCodec {
    /// STUB (RED) — Viterbi-encodes an RS stream (not yet implemented).
    pub fn encode(&self, _rs_stream: &[u8]) -> Vec<u8> {
        Vec::new()
    }

    /// STUB (RED) — inverts [`encode`](Self::encode) (not yet implemented).
    pub fn decode(&self, _blob_body: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::ViterbiCodec;
    use crate::error::CryptoError;
    use crate::{
        HEADER_LEN, MAX_BLOB_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN, RS_BLOCK, RS_DATA, TAG_LEN,
        TERMINATION_OVERHEAD, VITERBI_CHUNK,
    };
    use viterbi::{CodeParams, ViterbiEncoder};

    /// Ceil-div `a / b` (manual — MSRV 1.70, `div_ceil` is 1.73+).
    fn ceil_div(a: usize, b: usize) -> usize {
        (a + b - 1) / b
    }

    /// P0-3: the single-chunk termination relation `enc.len() == 2L + 2` holds
    /// against the real `viterbi` 0.0.1 crate, and the codec round-trips.
    #[test]
    fn test_p0_3_viterbi_termination_length_and_roundtrip() {
        let v = ViterbiCodec;
        for l in [RS_BLOCK, 2 * RS_BLOCK, 5 * RS_BLOCK] {
            let s: Vec<u8> = (0..l).map(|i| i as u8).collect();
            let enc = v.encode(&s);
            assert_eq!(
                enc.len(),
                2 * l + 2,
                "spec 2L+2 must match viterbi 0.0.1 for single chunk (P0-3), L={l}"
            );
            assert_eq!(v.decode(&enc).unwrap(), s, "single-chunk round-trip");
        }
    }

    /// P0-3: a stream larger than one `VITERBI_CHUNK` is Viterbi-encoded in
    /// per-chunk sub-blocks, each with its own `+2` tail, so the total length is
    /// `2L + 2·num_chunks`; the codec still round-trips exactly.
    #[test]
    fn test_p0_3_viterbi_multi_chunk_length_and_roundtrip() {
        let v = ViterbiCodec;
        let l = VITERBI_CHUNK + RS_BLOCK; // exactly two chunks
        let num_chunks = ceil_div(l, VITERBI_CHUNK);
        assert_eq!(num_chunks, 2, "test fixture is a two-chunk stream");
        let s: Vec<u8> = (0..l).map(|i| i as u8).collect();
        let enc = v.encode(&s);
        assert_eq!(
            enc.len(),
            2 * l + 2 * num_chunks,
            "multi-chunk length is 2L + 2·num_chunks (per-chunk tail)"
        );
        assert_eq!(v.decode(&enc).unwrap(), s, "multi-chunk round-trip");
    }

    /// Reference anchor (P0-3 / SR-F5): the underlying `viterbi` crate reproduces
    /// the independent CCSDS 131.0-B impulse response `[0xBA, 0x48]`, so the blob
    /// format is locked against a *reference-validated* Viterbi, not a
    /// self-referential one.
    #[test]
    fn test_p0_3_viterbi_reproduces_ccsds_reference_impulse() {
        let enc = ViterbiEncoder::new(CodeParams::ccsds_r1_2()).expect("CCSDS params valid");
        let impulse = enc.encode_bits(&[0x80], 1).expect("single-bit encode");
        assert_eq!(
            impulse.bytes.as_slice(),
            [0xBA, 0x48],
            "codec must match the hand-traced CCSDS impulse response"
        );
    }

    /// SR-F3: an isolated bit error in the coded stream is corrected by the inner
    /// Viterbi code — the exact original RS stream is recovered.
    #[test]
    fn test_sr_f3_corrects_isolated_bit_error_within_capacity() {
        let v = ViterbiCodec;
        let s: Vec<u8> = (0..2 * RS_BLOCK).map(|i| (i * 7) as u8).collect();
        let mut enc = v.encode(&s);
        let mid = enc.len() / 2;
        enc[mid] ^= 0x01; // flip a single coded bit — within correction capacity
        assert_eq!(
            v.decode(&enc).unwrap(),
            s,
            "one bit error is corrected, original recovered"
        );
    }

    /// SR-F3 / SC-6: a malformed body whose length is inconsistent with the
    /// per-chunk coded formula is a typed `InvalidInput`, never a panic.
    #[test]
    fn test_sr_f3_malformed_body_is_typed_invalid_input_not_panic() {
        let v = ViterbiCodec;
        // Odd length: coded bodies are always even (2·il + 2).
        assert!(matches!(
            v.decode(&[0u8; 5]),
            Err(CryptoError::InvalidInput(_))
        ));
        // Even but too short to be a valid chunk body (min body is 4 bytes).
        assert!(matches!(
            v.decode(&[0u8; 2]),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    /// SR-F3: the empty stream round-trips to empty (degenerate identity).
    #[test]
    fn test_sr_f3_empty_stream_roundtrips() {
        let v = ViterbiCodec;
        assert!(v.encode(&[]).is_empty());
        assert_eq!(v.decode(&[]).unwrap(), Vec::<u8>::new());
    }

    /// P0-3 / P0-5 (format lock): `MAX_BLOB_LEN` uses the **per-chunk** Viterbi
    /// tail — `rs_max·2 + TERMINATION_OVERHEAD·ceil(rs_max / VITERBI_CHUNK)` —
    /// not a single aggregate tail, and `VITERBI_CHUNK` is a valid RS-aligned,
    /// under-cap block size.
    // Constant-pinning regression: asserting on compile-time constants is the
    // intent (guards the pinned wire-format arithmetic), so
    // `assertions_on_constants` is a false positive here.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_p0_3_max_blob_len_uses_per_chunk_viterbi_tail() {
        assert_eq!(VITERBI_CHUNK % RS_BLOCK, 0, "chunk aligns to RS codewords");
        assert!(
            VITERBI_CHUNK * 8 <= 1_000_000,
            "chunk info bits under crate cap"
        );

        let protected_max = MAX_PLAINTEXT_LEN + HEADER_LEN + NONCE_LEN + TAG_LEN;
        let rs_max = ceil_div(protected_max, RS_DATA) * RS_BLOCK;
        let viterbi_chunks = ceil_div(rs_max, VITERBI_CHUNK);
        let expected = rs_max * 2 + TERMINATION_OVERHEAD * viterbi_chunks;
        assert_eq!(
            MAX_BLOB_LEN, expected,
            "MAX_BLOB_LEN must account for a Viterbi tail per chunk"
        );
    }
}
