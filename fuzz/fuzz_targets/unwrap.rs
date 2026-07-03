// Author: Julian Bolivar
// Version: 1.0.0
// Date: 2026-07-03
//! Fuzz target: the public envelope unwrap door (`CryptoVault::unwrap_key`).
//!
//! SR-R5 / P0-4: arbitrary input, treated as the base64 envelope blob, MUST
//! always **return** a typed `Result` — never panic, never over-allocate, never
//! reveal key material. `unwrap_key` is the raw-byte sibling of
//! `decrypt_with_key` (no trailing UTF-8 validation), so it exercises the same
//! decrypt pipeline over the DEK/KEK envelope path. See `docs/no-panic.md`.

#![no_main]

use libfuzzer_sys::fuzz_target;

use cryptovault::vault::CryptoVault;

/// Fixed KEK — the no-panic contract is independent of the key (a wrong KEK
/// simply fails the AEAD tag with a typed error).
const KEK: [u8; 32] = [0x42u8; 32];

fuzz_target!(|data: &[u8]| {
    let vault = CryptoVault::default();
    let wrapped = String::from_utf8_lossy(data);
    // Contract: returns Ok/Err, never panics.
    let _ = vault.unwrap_key(&KEK, &wrapped);
});
