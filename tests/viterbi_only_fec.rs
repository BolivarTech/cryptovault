// Author: Julian Bolivar
// Version: 0.3.0
// Date: 2026-07-07
//! Integration scenarios for the `ViterbiOnlyFec` strategy (v0.3.0): AEAD +
//! Viterbi-only channel resilience, exercised end-to-end through the public
//! envelope API (`wrap_key`/`unwrap_key`) of a `CryptoVault` with `ViterbiOnlyFec`
//! injected — no Reed-Solomon, no interleaver.
//!
//! ## Channel model
//!
//! A "channel error" is injected by base64-decoding the blob, flipping bits in
//! the Viterbi-encoded stream, and re-base64-encoding — exactly what a caller
//! would receive off a noisy wire. Hard-decision Viterbi corrects a bounded number
//! of **isolated** bit errors (SC-2); a dense burst beyond capacity mis-decodes,
//! and the AEAD tag then rejects the result (SC-3) — never a silently-wrong DEK
//! (the AEAD is the sole integrity anchor). Mirrors `tests/scenarios.rs` for the
//! Viterbi-only wire format.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use cryptovault::cipher::Aes256GcmSivCipher;
use cryptovault::error::CryptoError;
use cryptovault::fec::{ErrorCorrection, ViterbiOnlyFec};
use cryptovault::kdf::Argon2Kdf;
use cryptovault::vault::CryptoVault;
use cryptovault::{KEY_LEN, SALT_LEN, VITERBI_CHUNK};

/// A fixed pre-derived master (KEK). `wrap_key`/`unwrap_key` take a pre-derived
/// key, so no Argon2 runs on this path — the tests stay fast.
const MASTER: [u8; KEY_LEN] = [0x42u8; KEY_LEN];
/// A fixed per-context salt, bound as AAD by the envelope path.
const SALT: [u8; SALT_LEN] = [0xA5u8; SALT_LEN];

/// Builds an AEAD + Viterbi-only vault (no RS, no interleaver).
fn viterbi_only_vault() -> CryptoVault {
    CryptoVault::new(
        Box::new(Argon2Kdf),
        Box::new(Aes256GcmSivCipher),
        Box::new(ViterbiOnlyFec),
    )
}

/// Flips a single bit at each `(byte, bit)` position of the base64-decoded blob,
/// then re-encodes — isolated bit errors on the wire, the case a hard-decision
/// Viterbi code is designed to correct. Positions past the end are ignored.
fn flip_bits(blob: &str, positions: &[(usize, u8)]) -> String {
    let mut raw = STANDARD.decode(blob).expect("our own blob is valid base64");
    for &(byte, bit) in positions {
        if byte < raw.len() {
            raw[byte] ^= 1 << (bit % 8);
        }
    }
    STANDARD.encode(&raw)
}

/// Flips `count` consecutive bytes starting at `start` — a dense burst well beyond
/// the Viterbi code's isolated-error capacity — then re-encodes. Clamped so it
/// never panics.
fn corrupt_burst(blob: &str, start: usize, count: usize) -> String {
    let mut raw = STANDARD.decode(blob).expect("our own blob is valid base64");
    let end = start.saturating_add(count).min(raw.len());
    for b in raw.iter_mut().take(end).skip(start) {
        *b ^= 0xFF;
    }
    STANDARD.encode(&raw)
}

/// SC-1 (SR-F4): clean-channel round-trip through AEAD + Viterbi-only recovers the
/// exact payload across sizes that straddle Viterbi chunk boundaries.
#[test]
fn test_sc1_viterbi_only_clean_channel_roundtrip() {
    let v = viterbi_only_vault();
    for &len in &[0usize, 1, 33, 223, 300, 1024] {
        let dek: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
        let blob = v.wrap_key(&MASTER, &SALT, &dek).unwrap();
        let recovered = v.unwrap_key(&MASTER, &SALT, &blob).unwrap();
        assert_eq!(&*recovered, &dek, "clean round-trip, len={len}");
    }
}

/// SC-8 (SR-F1): the empty payload is a valid degenerate case end-to-end.
#[test]
fn test_sc8_viterbi_only_empty_payload_roundtrips() {
    let v = viterbi_only_vault();
    let blob = v.wrap_key(&MASTER, &SALT, &[]).unwrap();
    let recovered = v.unwrap_key(&MASTER, &SALT, &blob).unwrap();
    assert!(recovered.is_empty(), "empty DEK round-trips to empty");
}

/// SC-2 (SR-F3): a few isolated single-bit channel errors — within the
/// hard-decision Viterbi correction capacity — are corrected and the exact
/// payload is recovered.
#[test]
fn test_sc2_viterbi_only_isolated_bit_errors_recover() {
    let v = viterbi_only_vault();
    let dek: Vec<u8> = (0..48u8).collect();
    let blob = v.wrap_key(&MASTER, &SALT, &dek).unwrap();
    let raw_len = STANDARD.decode(&blob).unwrap().len();
    // Isolated bit flips spread far apart — the case Viterbi corrects.
    let positions = [(raw_len / 5, 1u8), (raw_len / 2, 4), (3 * raw_len / 4, 7)];
    let corrupted = flip_bits(&blob, &positions);
    let recovered = v
        .unwrap_key(&MASTER, &SALT, &corrupted)
        .unwrap_or_else(|e| panic!("isolated bit errors must be corrected, got {e:?}"));
    assert_eq!(&*recovered, &dek, "isolated-error recovery is exact");
}

/// SC-3 (SR-R6): corruption beyond the Viterbi capacity (a dense byte burst) yields
/// a typed error — never a silently-wrong DEK (the AEAD tag is the anchor).
#[test]
fn test_sc3_viterbi_only_beyond_capacity_is_typed_error() {
    let v = viterbi_only_vault();
    let dek: Vec<u8> = (0..64u8).collect();
    let blob = v.wrap_key(&MASTER, &SALT, &dek).unwrap();
    let raw_len = STANDARD.decode(&blob).unwrap().len();
    let corrupted = corrupt_burst(&blob, raw_len / 4, raw_len / 2);
    match v.unwrap_key(&MASTER, &SALT, &corrupted) {
        Err(CryptoError::ErrorCorrection(_))
        | Err(CryptoError::Cipher(_))
        | Err(CryptoError::InvalidInput(_)) => {}
        Err(other) => panic!("unexpected error variant: {other:?}"),
        Ok(p) => assert_ne!(
            &*p, &dek,
            "beyond-capacity corruption must never recover the exact DEK"
        ),
    }
}

/// KAT (SR-F3 / P0-3): the Viterbi-only framing relation — a single-chunk
/// protected payload of `L` bytes encodes to exactly `2L + 2` blob-body bytes, and
/// a payload spanning two chunks to `2L + 2·2`.
#[test]
fn test_kat_viterbi_only_framing_length_relation() {
    let fec = ViterbiOnlyFec;
    for &l in &[1usize, 33, 300, 1024] {
        let body = fec.encode(&vec![0x5Au8; l]);
        assert_eq!(body.len(), 2 * l + 2, "single-chunk 2L+2, L={l}");
    }
    let l = VITERBI_CHUNK + 100;
    let body = fec.encode(&vec![0x5Au8; l]);
    assert_eq!(body.len(), 2 * l + 4, "two-chunk 2L + 2*2, L={l}");
}
