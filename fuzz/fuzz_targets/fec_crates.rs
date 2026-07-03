// Author: Julian Bolivar
// Version: 1.0.0
// Date: 2026-07-03
//! Fuzz target: the own FEC crates driven DIRECTLY (SR-F5).
//!
//! `reedsolomon` 0.1.0 and `viterbi` 0.0.1 are early-stage BolivarTech crates.
//! The concatenated-FEC no-panic contract must hold *across the FEC boundary*
//! (SR-R5): adversarial input SHALL surface as a typed error, never a panic from
//! the FEC crates. `decrypt`/`unwrap` exercise them behind cryptovault's
//! structural gates; this target exercises them **unguarded**, on arbitrary
//! bytes, to prove the crates themselves are panic-safe (the second layer of the
//! four-layer strategy in `spec-behavior-base.md` / P0-4).
//!
//! Any panic found here is a release blocker and becomes a permanent regression
//! test (upstream fix / fork of the offending crate).

#![no_main]

use libfuzzer_sys::fuzz_target;

use reedsolomon::ReedSolomon;
use viterbi::{CcsdsViterbiDecoder, CodeParams, CodedBlock};

/// Upper bound on the crate cap so a huge arbitrary `nbits` maps to a typed
/// `InputTooLong`, never an unbounded allocation.
const MAX_INFO_BITS: usize = 1_000_000;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // First byte is an arbitrary selector for the RS truncation length and the
    // Viterbi tail-bit slack; the rest is the payload fed to both codecs.
    let sel = data[0] as usize;
    let payload = &data[1..];

    // --- Reed-Solomon RS(255,223), driven directly on arbitrary bytes ---
    let rs = ReedSolomon::default();
    // `original_len` is bounded (<= 255 * 4) so a hostile length can never force
    // an over-allocation; the decoder must still return a typed Result.
    let original_len = sel.saturating_mul(4);
    let _ = rs.decode(payload, original_len);
    // The framed variant parses its own length prefix from arbitrary bytes.
    let _ = rs.decode_framed(payload);

    // --- Viterbi K=7 R=1/2 decode_block, driven directly on arbitrary bytes ---
    if let Ok(mut decoder) = CcsdsViterbiDecoder::new(CodeParams::ccsds_r1_2(), MAX_INFO_BITS) {
        // Arbitrary coded-bit count: usually 8*len minus a tail slack, but the
        // selector also probes off-by-one / oversized nbits. All must return a
        // typed DecodeError, never panic.
        let nbits = payload.len().saturating_mul(8).saturating_sub(sel % 8);
        let block = CodedBlock {
            bytes: payload.to_vec(),
            nbits,
        };
        let _ = decoder.decode_block(&block);
    }
});
