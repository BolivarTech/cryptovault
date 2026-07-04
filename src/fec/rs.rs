// Author: Julian Bolivar
// Version: 0.2.1
// Date: 2026-07-03
//! Reed-Solomon outer FEC: the [`ReedSolomonCodec`] strategy over the author's
//! own `reedsolomon` 0.1.0 crate — RS(255, 223) / CCSDS over GF(2^8) (SR-F1).

use reedsolomon::{ReedSolomon, RsError};

use crate::error::{CryptoError, Result};
use crate::fec::ErrorCorrection;
use crate::{MAX_BLOB_LEN, RS_BLOCK, RS_DATA};

/// Reed-Solomon `RS(255, 223)` outer code (SR-F1).
///
/// The default CCSDS geometry: each 223-byte data chunk is expanded to a
/// 255-byte codeword (32 parity bytes), correcting up to 16 symbol errors per
/// codeword. A fieldless strategy struct — construct it directly
/// (`ReedSolomonCodec`); it holds no state.
///
/// Chunking (223→255 per block), final-chunk zero-padding, and `pre_len`
/// truncation are delegated to `reedsolomon` 0.1.0 (DRY — not re-rolled); this
/// wrapper adds the structural length guard and maps `RsError` onto the crate's
/// typed [`CryptoError`] domain.
pub struct ReedSolomonCodec;

/// Number of whole [`RS_BLOCK`]-byte codewords in a `byte_len`-byte RS stream,
/// or `None` if `byte_len` is not a whole multiple of [`RS_BLOCK`] (a
/// structurally invalid stream — SR-F1 / SR-R3).
const fn block_count(byte_len: usize) -> Option<usize> {
    if byte_len.is_multiple_of(RS_BLOCK) {
        Some(byte_len / RS_BLOCK)
    } else {
        None
    }
}

impl ErrorCorrection for ReedSolomonCodec {
    fn encode(&self, data: &[u8]) -> Vec<u8> {
        ReedSolomon::default()
            .encode(data)
            // Statically unreachable: `encode` only errors on a `usize` overflow
            // of the ~1.14× encoded length, impossible for any `data` already
            // held in memory (`data.len() <= isize::MAX`); the blob layer
            // additionally caps plaintext at `MAX_PLAINTEXT_LEN`.
            .expect("RS encode of an in-memory buffer cannot overflow usize")
    }

    /// Reed-Solomon-decodes `encoded`, correcting up to 16 symbol errors per
    /// codeword and truncating to `pre_len`.
    ///
    /// # ⚠️ No self-enforced length cap (N4)
    /// This direct method validates only whole-codeword framing; it does **not**
    /// enforce [`MAX_BLOB_LEN`] (that cap lives in
    /// [`validate_pre_fec`](Self::validate_pre_fec) and the vault decrypt path). A
    /// caller using this codec directly, bypassing the vault, **must impose its own
    /// input-length cap** to bound decode CPU/memory.
    fn decode(&self, encoded: &[u8], pre_len: usize) -> Result<Vec<u8>> {
        // SR-F1 / SR-R3: an RS stream is a whole number of `RS_BLOCK`-byte
        // codewords. Reject a structurally invalid length up front so the FEC
        // crate never parses adversarial framing (no panic on hostile input).
        if block_count(encoded.len()).is_none() {
            // SR-R7: generic, oracle-free message — no exact length or FEC-internal
            // detail is echoed back to a probing attacker.
            return Err(CryptoError::InvalidInput("malformed blob".into()));
        }
        ReedSolomon::default()
            .decode(encoded, pre_len)
            // SR-R7: map onto fixed, generic messages — never surface the
            // `reedsolomon` crate's internal error string (which can embed
            // codeword indices / lengths that leak structural specifics).
            .map_err(|e| match e {
                RsError::Uncorrectable(_) => {
                    CryptoError::ErrorCorrection("forward error correction failed".into())
                }
                RsError::InvalidInput(_) => CryptoError::InvalidInput("malformed blob".into()),
            })
    }

    /// Validates the RS-only framing and returns the recovered data length
    /// (SR-R3a / SR-R4).
    ///
    /// An RS blob (this codec used standalone, without the inner Viterbi/
    /// interleaver) is a whole number of [`RS_BLOCK`]-byte codewords: caps
    /// `received.len() <= `[`MAX_BLOB_LEN`], requires at least one codeword and a
    /// whole-codeword length, and returns the recovered data length
    /// `(blocks · RS_DATA)`. Never panics on adversarial input.
    fn validate_pre_fec(&self, received: &[u8]) -> Result<usize> {
        if received.len() > MAX_BLOB_LEN {
            // SR-R7: a length cap is not an oracle, but avoid echoing the exact
            // received length — a fixed, generic message suffices.
            return Err(CryptoError::InvalidInput(
                "input exceeds maximum size".into(),
            ));
        }
        match block_count(received.len()) {
            Some(blocks) if blocks >= 1 => Ok(blocks * RS_DATA),
            // SR-R7: generic, oracle-free structural rejection.
            _ => Err(CryptoError::InvalidInput("malformed blob".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ReedSolomonCodec;
    use crate::error::CryptoError;
    use crate::fec::ErrorCorrection;
    use crate::RS_BLOCK;

    /// SR-F1: a multi-chunk payload is RS-encoded to whole codewords and a
    /// within-capacity burst (≤16 symbol errors in one codeword) is corrected.
    #[test]
    fn test_sr_f1_rs_corrects_within_capacity_and_chunks() {
        let rs = ReedSolomonCodec;
        let data = b"payload longer than one 223-byte chunk .....".repeat(10);
        let mut enc = rs.encode(&data);
        assert_eq!(enc.len() % RS_BLOCK, 0, "encoded stream is whole codewords");
        for byte in enc.iter_mut().take(16) {
            *byte ^= 0xFF; // 16 errors in the first codeword — at capacity
        }
        assert_eq!(rs.decode(&enc, data.len()).unwrap(), data);
    }

    /// SR-F1 / SR-R3: an RS stream whose length is not a whole multiple of
    /// `RS_BLOCK` is a typed `InvalidInput`, never a panic.
    #[test]
    fn test_sr_f1_invalid_rs_stream_length_is_typed_not_panic() {
        let rs = ReedSolomonCodec;
        assert!(matches!(
            rs.decode(&[0u8; RS_BLOCK + 1], 1),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    /// SR-F1 boundary: the smallest real protected payload (33 bytes — the
    /// empty-plaintext degenerate case: header + nonce + tag) is exactly one RS
    /// codeword and round-trips unchanged.
    #[test]
    fn test_sr_f1_minimal_single_codeword_payload_roundtrips() {
        let rs = ReedSolomonCodec;
        let data = vec![0xABu8; 33];
        let enc = rs.encode(&data);
        assert_eq!(enc.len(), RS_BLOCK, "33-byte payload → one codeword");
        assert_eq!(rs.decode(&enc, data.len()).unwrap(), data);
    }
}
