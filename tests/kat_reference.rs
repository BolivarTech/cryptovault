// Author: Julian Bolivar
// Version: 1.0.0
// Date: 2026-07-03
//! Task 0b — FEC de-risk: independent-reference KATs + early probes.
//!
//! This suite validates the two own FEC crates (`reedsolomon` 0.1.0 and
//! `viterbi` 0.0.1, both BolivarTech) against **genuinely independent
//! references** and pins the Viterbi termination overhead that drives
//! [`cryptovault::MAX_BLOB_LEN`], **before** the blob format is locked (Task 9,
//! P0-3). It de-risks the whole concatenated-FEC plan by proving the crate APIs
//! behave as the plan's length model and error contract assume.
//!
//! # Reference provenance (independence is the point)
//!
//! * **Reed-Solomon.** The RS(255,223) parity reference [`RS255_REF_PARITY`] is
//!   produced by the third-party Python **`reedsolo`** library
//!   (`fcr=112, prim=0x187, gen=2` — the CCSDS convention), an implementation
//!   unrelated to the `reedsolomon` crate under test. Byte-identical parity from
//!   two independent codecs is the cross-check.
//! * **Viterbi.** The CCSDS `K=7, R=1/2` impulse response
//!   [`VITERBI_CCSDS_IMPULSE`] `= [0xBA, 0x48]` is derived directly from the
//!   published **CCSDS 131.0-B** generator polynomials `G1 = 0o171`,
//!   `G2 = 0o133` (G2 output inverted), MSB-first — not copied from the crate.
//!
//! These are provisional independent references sufficient to de-risk Task 0b.
//! The full, signed external FEC review remains a separate release gate
//! (Task 25); until then the Viterbi vector is a single hand-traced impulse and
//! the RS vector is a single `reedsolo`-sourced codeword — adequate here, not a
//! substitute for that review.

use reedsolomon::{ReedSolomon, RsError};
use viterbi::{CcsdsViterbiDecoder, CodeParams, ViterbiEncoder};

use cryptovault::{RS_BLOCK, RS_DATA, RS_PARITY, TERMINATION_OVERHEAD};

/// Independent RS(255,223) parity reference: the 32 parity bytes the third-party
/// `reedsolo` library appends to the data block `0, 1, .., 222`
/// (`fcr=112, prim=0x187, gen=2`). Cross-checks the `reedsolomon` crate's encoder.
const RS255_REF_PARITY: [u8; RS_PARITY] = [
    158, 231, 74, 155, 39, 244, 58, 206, 26, 141, 128, 252, 255, 161, 132, 86, 196, 126, 234, 128,
    90, 90, 160, 125, 98, 145, 75, 186, 191, 203, 254, 81,
];

/// Independent CCSDS `K=7, R=1/2` impulse response `[0xBA, 0x48]` — one info bit
/// `1` (MSB of `0x80`) followed by the 6-bit zero tail, byte-packed MSB-first,
/// hand-traced from the CCSDS 131.0-B polynomials (`G1 = 0o171`, `G2 = 0o133`,
/// G2 inverted).
const VITERBI_CCSDS_IMPULSE: [u8; 2] = [0xBA, 0x48];

/// Canonical RS(255,223) data block used across the RS cross-checks: `0..=222`.
fn rs255_data() -> Vec<u8> {
    (0u8..=222).collect()
}

// ---------------------------------------------------------------------------
// Step 2 — Viterbi termination-overhead probe (P0-3, SR-F3).
// Guards cryptovault::TERMINATION_OVERHEAD (and thus MAX_BLOB_LEN) against the
// REAL viterbi 0.0.1 output length. If the crate's termination ever changes,
// this test fails and forces a constant correction before the format is locked.
// ---------------------------------------------------------------------------

/// The `viterbi` 0.0.1 encoder expands an `L`-byte input to exactly `2L + 2`
/// bytes (rate-1/2 doubling of `8L + 6` bits, byte-packed), so the per-block
/// Viterbi termination overhead is exactly [`TERMINATION_OVERHEAD`] `= 2`.
#[test]
fn test_p0_3_viterbi_termination_overhead_is_two_bytes_per_block() {
    let enc = ViterbiEncoder::new(CodeParams::ccsds_r1_2()).expect("CCSDS params are valid");
    // Multiples of RS_BLOCK: representative concatenated-FEC stream lengths.
    for blocks in [1usize, 2, 5] {
        let l = blocks * RS_BLOCK;
        let stream: Vec<u8> = (0..l).map(|i| i as u8).collect();
        let coded = enc.encode(&stream).expect("encode within cap");
        // Coded bit length: (8L info + 6 tail) * 2, byte-packed => 2L + 2 bytes.
        assert_eq!(coded.nbits, (8 * l + 6) * 2, "coded bit count = (8L+6)*2");
        assert_eq!(
            coded.bytes.len(),
            2 * l + TERMINATION_OVERHEAD,
            "viterbi output must be 2L + TERMINATION_OVERHEAD (L={l})"
        );
    }
    // The overhead constant itself is pinned to the measured per-block value.
    assert_eq!(
        TERMINATION_OVERHEAD, 2,
        "measured viterbi 0.0.1 per-block tail"
    );
}

/// The Viterbi encoder reproduces the independent CCSDS impulse response, and a
/// clean round-trip through the decoder recovers the exact input — the encode /
/// decode API pair works as the plan assumes.
#[test]
fn test_sr_f3_viterbi_matches_ccsds_impulse_and_round_trips() {
    let enc = ViterbiEncoder::new(CodeParams::ccsds_r1_2()).expect("CCSDS params are valid");
    let impulse = enc.encode_bits(&[0x80], 1).expect("single-bit encode");
    assert_eq!(
        impulse.bytes.as_slice(),
        VITERBI_CCSDS_IMPULSE,
        "encoder must match the hand-traced CCSDS impulse"
    );
    assert_eq!(impulse.nbits, 14, "7 stages * 2 output bits");

    // Clean-channel round-trip over one RS codeword's worth of bytes.
    let stream: Vec<u8> = (0..RS_BLOCK as u32).map(|i| i as u8).collect();
    let coded = enc.encode(&stream).expect("encode within cap");
    let mut dec =
        CcsdsViterbiDecoder::new(CodeParams::ccsds_r1_2(), 100_000).expect("decoder config valid");
    let decoded = dec.decode_block(&coded).expect("clean decode");
    assert_eq!(
        decoded.bytes, stream,
        "clean Viterbi round-trip is identity"
    );
}

// ---------------------------------------------------------------------------
// Step 3 / 3b — RS cross-check against the independent reference (SR-F1).
// ---------------------------------------------------------------------------

/// The `reedsolomon` crate's RS(255,223) encoder produces byte-identical parity
/// to the independent `reedsolo` reference, and corrects up to 16 byte errors in
/// a block (`t = RS_PARITY / 2`), recovering the exact original.
#[test]
fn test_sr_f1_rs_encode_matches_reference_parity_and_corrects_within_capacity() {
    let rs = ReedSolomon::default();
    let data = rs255_data();
    let encoded = rs.encode(&data).expect("RS encode");
    assert_eq!(
        encoded.len(),
        RS_BLOCK,
        "one 223-byte block => one 255 codeword"
    );
    assert_eq!(
        &encoded[..RS_DATA],
        data.as_slice(),
        "systematic: data prefix intact"
    );
    assert_eq!(
        &encoded[RS_DATA..],
        RS255_REF_PARITY,
        "crate parity must match the independent reedsolo reference"
    );

    // Corrupt exactly t = 16 bytes (within capacity) => exact recovery.
    let mut corrupted = encoded.clone();
    for i in 0..(RS_PARITY / 2) {
        corrupted[i * 3] ^= 0x5A;
    }
    assert_eq!(
        rs.decode(&corrupted, data.len())
            .expect("<=16 errors correctable"),
        data,
        "RS recovers the exact original within correction capacity"
    );
}

/// Beyond the correction capacity (17 > `t = 16` errors) the decoder fails loud
/// with [`RsError::Uncorrectable`] — it never returns wrong-but-plausible data.
#[test]
fn test_sr_f1_rs_fails_loud_beyond_capacity() {
    let rs = ReedSolomon::default();
    let data = rs255_data();
    let encoded = rs.encode(&data).expect("RS encode");

    let mut corrupted = encoded.clone();
    for byte in corrupted.iter_mut().take((RS_PARITY / 2) + 1) {
        *byte ^= 0xFF;
    }
    assert!(
        matches!(
            rs.decode(&corrupted, data.len()),
            Err(RsError::Uncorrectable(_))
        ),
        "17 errors must be declared Uncorrectable, never mis-corrected"
    );

    // A structurally invalid stream (not a whole number of 255-byte blocks) is
    // rejected as InvalidInput, not a panic.
    assert!(
        matches!(
            rs.decode(&[0u8; RS_BLOCK + 1], 1),
            Err(RsError::InvalidInput(_))
        ),
        "non-multiple-of-255 stream is a typed InvalidInput"
    );
}
