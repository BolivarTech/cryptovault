// Author: Julian Bolivar
// Version: 0.3.0
// Date: 2026-07-07
//! Fuzz target: the string decrypt door of a **Viterbi-only** vault
//! (`CryptoVault` with `ViterbiOnlyFec` injected) — v0.3.0.
//!
//! SR-R5 / P0-4: arbitrary input, treated as the base64 blob string, MUST always
//! **return** a typed `Result` (`Ok`/`Err`) — never panic, never over-allocate.
//! This drives the Viterbi-only decrypt path internally: base64-length cap →
//! strict base64 decode → `ViterbiOnlyFec::validate_pre_fec` (structural gate,
//! `MAX_BLOB_LEN` cap + chunked-Viterbi framing) → Viterbi decode → header
//! validation → AES-256-GCM-SIV open → UTF-8 validation. It complements the
//! concatenated-FEC `decrypt` target, covering the AEAD + Viterbi-only strategy's
//! distinct (no-RS, no-interleaver) framing.

#![no_main]

use libfuzzer_sys::fuzz_target;

use cryptovault::cipher::Aes256GcmSivCipher;
use cryptovault::fec::ViterbiOnlyFec;
use cryptovault::kdf::Argon2Kdf;
use cryptovault::vault::CryptoVault;

/// A fixed key: the no-panic contract is key-independent (a wrong key merely fails
/// the AEAD tag), so a constant key maximises reachable-code coverage without the
/// fuzzer wasting energy on the key space.
const KEY: [u8; 32] = [0x42u8; 32];

fuzz_target!(|data: &[u8]| {
    // `decrypt_with_key` takes a pre-derived key, so Argon2 never runs on this
    // path — the fuzzer exercises the FEC + AEAD decode, not the KDF.
    let vault = CryptoVault::new(
        Box::new(Argon2Kdf),
        Box::new(Aes256GcmSivCipher),
        Box::new(ViterbiOnlyFec),
    );
    // Arbitrary bytes as a (lossy) UTF-8 string — the strict base64 decoder rejects
    // any non-canonical alphabet/padding with a typed Encoding error.
    let blob = String::from_utf8_lossy(data);
    // Contract: this returns; a panic here is a release-blocking bug.
    let _ = vault.decrypt_with_key(&KEY, &blob);
});
