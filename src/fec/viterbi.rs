// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Viterbi inner FEC: the [`ViterbiCodec`] wrapper over the author's own
//! `viterbi` 0.0.1 crate — CCSDS `K=7, R=1/2` hard-decision convolutional code
//! (SR-F3 / P0-3).

use viterbi::{CcsdsViterbiDecoder, CodeParams, CodedBlock, DecodeError};

use crate::error::{CryptoError, Result};
use crate::VITERBI_CHUNK;

/// Zero-tail overhead of a single Viterbi sub-block (`2L + 2` ⇒ `+2` bytes).
///
/// Named locally to keep the length arithmetic self-documenting; equal to the
/// crate-level [`crate::TERMINATION_OVERHEAD`].
const TAIL_BYTES: usize = crate::TERMINATION_OVERHEAD;

/// Coded-body length (bytes) of one **full** `VITERBI_CHUNK` sub-block.
///
/// Viterbi rate-1/2 with a 6-bit zero tail maps `L` info bytes to `2L + 2`
/// coded bytes (the final byte is padded by exactly 4 bits — see
/// [`coded_nbits`]). A full chunk therefore occupies `2·VITERBI_CHUNK + 2`
/// bytes on the wire; every chunk but the last has exactly this length, which is
/// what lets the receiver reconstruct the chunk boundaries from the framed body
/// length alone.
const FULL_CHUNK_BODY: usize = 2 * VITERBI_CHUNK + TAIL_BYTES;

/// Minimum valid coded-body length (bytes): the smallest chunk encodes one info
/// byte as `2·1 + 2 = 4` coded bytes.
const MIN_CHUNK_BODY: usize = 2 + TAIL_BYTES;

/// Exact coded bit count of a `body_len`-byte Viterbi sub-block.
///
/// For `il` info bytes the encoder emits `(8·il + 6)·2 = 16·il + 12` coded bits
/// packed into `2·il + 2` bytes, so the final byte always carries exactly 4
/// padding bits. Inverting `body_len = 2·il + 2` gives `nbits = 8·body_len − 4`,
/// the value [`viterbi::CcsdsViterbiDecoder::decode_block`] needs to recover the
/// info length. `body_len` is a caller-validated even value `≥ MIN_CHUNK_BODY`.
const fn coded_nbits(body_len: usize) -> usize {
    8 * body_len - 4
}

/// CCSDS `K=7, R=1/2` hard-decision Viterbi inner code (SR-F3 / P0-3).
///
/// The innermost stage of the concatenated FEC: it wraps the author's own
/// `viterbi` 0.0.1 crate, adding **chunking** so a full-payload Reed-Solomon
/// stream (which exceeds the crate's single-block cap of
/// `MAX_SUPPORTED_INFO_BITS = 1_000_000` bits) is encoded in fixed
/// [`VITERBI_CHUNK`]-byte sub-blocks and mapping the crate's typed errors onto
/// the vault's [`CryptoError`] domain (never a panic on adversarial input).
///
/// A fieldless strategy struct — construct it directly (`ViterbiCodec`); it
/// holds no state. The pair is symmetric: [`encode`](Self::encode) is inverted
/// by [`decode`](Self::decode).
pub struct ViterbiCodec;

impl ViterbiCodec {
    /// Viterbi-encodes `rs_stream` in [`VITERBI_CHUNK`]-byte sub-blocks,
    /// concatenating the per-chunk coded bodies (SR-F3).
    ///
    /// This is the transmit (encrypt-side) path over the caller's own data, so
    /// it is infallible by contract. Each chunk is at most `VITERBI_CHUNK` bytes
    /// (`999_600` info bits) — well under the crate's `1_000_000`-bit cap — so
    /// the only residual failure the backing encoder can report is an OOM
    /// allocation, treated as statically unreachable here (the RS stream is
    /// already held in memory and capped at [`crate::MAX_BLOB_LEN`]).
    ///
    /// # Parameters
    /// - `rs_stream`: the interleaved Reed-Solomon stream to protect.
    ///
    /// # Returns
    /// The concatenated coded stream, length `2·rs_stream.len() + 2·num_chunks`
    /// where `num_chunks = ceil(rs_stream.len() / VITERBI_CHUNK)` (empty in, empty
    /// out).
    pub fn encode(&self, rs_stream: &[u8]) -> Vec<u8> {
        let encoder = viterbi::ViterbiEncoder::new(CodeParams::ccsds_r1_2())
            // Statically valid: `ccsds_r1_2()` is a fixed, well-formed profile.
            .expect("CCSDS K=7 R=1/2 parameters are statically valid");
        let mut out = Vec::new();
        for chunk in rs_stream.chunks(VITERBI_CHUNK) {
            let coded = encoder
                .encode(chunk)
                // Unreachable: `chunk.len() <= VITERBI_CHUNK`, i.e. `999_600`
                // info bits < the crate's `1_000_000`-bit cap; the only other
                // error is OOM on an already-held, length-capped buffer.
                .expect("chunk is within MAX_SUPPORTED_INFO_BITS");
            out.extend_from_slice(&coded.bytes);
        }
        out
    }

    /// Viterbi-decodes `blob_body`, inverting [`encode`](Self::encode) and
    /// returning the recovered Reed-Solomon stream (SR-F3 / P0-3).
    ///
    /// The chunk structure is derived from the framed body length alone: every
    /// sub-block but the last is exactly `2·VITERBI_CHUNK + 2` bytes, and the
    /// final (possibly shorter) sub-block carries the remainder. Hard-decision
    /// Viterbi is correction-only — an uncorrectable channel yields *wrong* bytes
    /// here, which the downstream Reed-Solomon and AEAD layers reject (the AEAD
    /// tag is the final integrity anchor); this stage errors only on a
    /// structurally malformed body or a backing-codec boundary failure.
    ///
    /// # Parameters
    /// - `blob_body`: the received, possibly-corrupted coded stream.
    ///
    /// # Returns
    /// The recovered RS stream (empty in, empty out).
    ///
    /// # Errors
    /// - [`CryptoError::InvalidInput`] if `blob_body`'s length is inconsistent
    ///   with the per-chunk coded formula (the final sub-block is not a valid
    ///   `2·il + 2` coded body) — rejected before the codec runs, never a panic.
    /// - [`CryptoError::ErrorCorrection`] if the backing decoder reports an
    ///   allocation failure.
    pub fn decode(&self, blob_body: &[u8]) -> Result<Vec<u8>> {
        if blob_body.is_empty() {
            return Ok(Vec::new());
        }
        let bodies = chunk_body_lengths(blob_body.len())?;
        let mut decoder = CcsdsViterbiDecoder::new(CodeParams::ccsds_r1_2(), VITERBI_CHUNK * 8)
            // Statically valid: `VITERBI_CHUNK * 8 = 999_600 <= 1_000_000`.
            .expect("max_info_bits is within MAX_SUPPORTED_INFO_BITS");
        let mut out = Vec::new();
        let mut offset = 0usize;
        for body_len in bodies {
            let coded = CodedBlock {
                bytes: blob_body[offset..offset + body_len].to_vec(),
                nbits: coded_nbits(body_len),
            };
            let decoded = decoder.decode_block(&coded).map_err(map_decode_error)?;
            out.extend_from_slice(&decoded.bytes);
            offset += body_len;
        }
        Ok(out)
    }
}

/// Reconstructs the per-chunk coded-body lengths from the total framed body
/// length (SR-F3 / SR-R2 — no bootstrapping on the still-encoded header).
///
/// All sub-blocks but the last are [`FULL_CHUNK_BODY`] bytes; the final one is
/// the remainder, which must be a valid coded body (even, `≥ MIN_CHUNK_BODY`).
///
/// # Errors
/// [`CryptoError::InvalidInput`] if the remainder is not a structurally valid
/// final coded body.
fn chunk_body_lengths(total: usize) -> Result<Vec<usize>> {
    let full = total / FULL_CHUNK_BODY;
    let rem = total % FULL_CHUNK_BODY;
    let mut bodies = vec![FULL_CHUNK_BODY; full];
    if rem != 0 {
        if rem < MIN_CHUNK_BODY || rem % 2 != 0 {
            return Err(CryptoError::InvalidInput(format!(
                "Viterbi body length {total} has an invalid final chunk of {rem} bytes"
            )));
        }
        bodies.push(rem);
    }
    Ok(bodies)
}

/// Derives the Reed-Solomon stream length `L` (bytes) that a `body_len`-byte
/// chunked-Viterbi body decodes to, validating the per-chunk structure
/// (SR-R3a / SR-F3).
///
/// This is the **single source of truth** for inverting [`ViterbiCodec::encode`]'s
/// chunking: it reuses [`chunk_body_lengths`] (the one place the chunk math
/// lives), so every caller — [`ViterbiCodec::decode`] via `chunk_body_lengths`
/// and the blob layer's `validate_pre_fec` via this function — derives the
/// identical `L`, byte-for-byte. Each sub-block of `b` coded bytes carries
/// `b / 2 - 1` info bytes (from `b = 2·il + 2`), so `L` is their sum. An empty
/// body yields `L = 0`.
///
/// # Parameters
/// - `body_len`: the total framed Viterbi body length in bytes.
///
/// # Returns
/// The derived RS-stream length `L`.
///
/// # Errors
/// [`CryptoError::InvalidInput`] if `body_len` is not structurally consistent
/// with the per-chunk coded formula (a final sub-block that is not a valid
/// `2·il + 2` coded body).
pub(crate) fn rs_len_from_body(body_len: usize) -> Result<usize> {
    Ok(chunk_body_lengths(body_len)?
        .into_iter()
        .map(|b| b / 2 - 1)
        .sum())
}

/// Maps a `viterbi` 0.0.1 [`DecodeError`] onto the vault's typed error domain.
///
/// A structural length inconsistency (`LengthMismatch` / `InputTooLong`) is
/// surfaced as [`CryptoError::InvalidInput`]; an allocation failure as
/// [`CryptoError::ErrorCorrection`]. No decode error carries codec-internal
/// detail (SR-R7).
fn map_decode_error(e: DecodeError) -> CryptoError {
    match e {
        DecodeError::LengthMismatch | DecodeError::InputTooLong { .. } => {
            CryptoError::InvalidInput("Viterbi coded body is structurally inconsistent".into())
        }
        DecodeError::AllocationFailed => {
            CryptoError::ErrorCorrection("Viterbi decode allocation failed".into())
        }
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
