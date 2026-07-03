// Author: Julian Bolivar
// Version: 1.0.0
// Date: 2026-07-03
//! Fuzz target: the public string decrypt door (`CryptoVault::decrypt_with_key`).
//!
//! SR-R5 / P0-4: arbitrary input, treated as the base64 blob string, MUST always
//! **return** a typed `Result` (`Ok`/`Err`) — never panic, never over-allocate.
//! This drives the full decrypt path internally: base64-length cap → strict
//! base64 decode → `validate_pre_fec` (structural gate) → Viterbi decode →
//! de-interleave → Reed-Solomon decode → header validation → AES-256-GCM-SIV
//! open → UTF-8 validation. See `docs/no-panic.md` for the entry-point → gate
//! audit table this target exercises.

#![no_main]

use libfuzzer_sys::fuzz_target;

use cryptovault::vault::CryptoVault;

/// A fixed key: the no-panic contract is key-independent (a wrong key merely
/// fails the AEAD tag), so a constant key maximises reachable-code coverage
/// without the fuzzer wasting energy on the key space.
const KEY: [u8; 32] = [0x42u8; 32];

fuzz_target!(|data: &[u8]| {
    let vault = CryptoVault::default();
    // Arbitrary bytes as a (lossy) UTF-8 string — the strict base64 decoder
    // rejects any non-canonical alphabet/padding with a typed Encoding error.
    let blob = String::from_utf8_lossy(data);
    // Contract: this returns; a panic here is a release-blocking bug.
    let _ = vault.decrypt_with_key(&KEY, &blob);
});
