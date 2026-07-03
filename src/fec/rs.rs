// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Reed-Solomon outer FEC: the [`ReedSolomonCodec`] strategy over the author's
//! own `reedsolomon` 0.1.0 crate — RS(255, 223) / CCSDS over GF(2^8) (SR-F1).

use crate::error::{CryptoError, Result};
use crate::fec::ErrorCorrection;

/// Reed-Solomon `RS(255, 223)` outer code (SR-F1).
///
/// The default CCSDS geometry: each 223-byte data chunk is expanded to a
/// 255-byte codeword (32 parity bytes), correcting up to 16 symbol errors per
/// codeword. A fieldless strategy struct — construct it directly
/// (`ReedSolomonCodec`); it holds no state.
pub struct ReedSolomonCodec;

impl ErrorCorrection for ReedSolomonCodec {
    fn encode(&self, _data: &[u8]) -> Vec<u8> {
        todo!("Task 6 Green: RS(255,223) systematic encode")
    }

    fn decode(&self, _encoded: &[u8], _pre_len: usize) -> Result<Vec<u8>> {
        todo!("Task 6 Green: structural guard + RS decode with error mapping")
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
