// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Task 20d — cross-cutting invariants (CERTIFICATION BAR).
//!
//! Safety- and hygiene-critical properties that cut across the whole public API:
//!
//! * **AEAD backstop (SR-R6, safety-critical):** any FEC/Viterbi mis-decode past
//!   correction capacity surfaces as a typed error — **never** a returned
//!   plaintext that differs from the original. The AEAD tag is the true integrity
//!   anchor; the FEC is resilience, not integrity.
//! * **Zeroize (SR-C8):** every secret-carrying return is `Zeroizing` (a
//!   compile-time type-bound assertion — the calls do not type-check if a return
//!   type ever loses its `Zeroizing` wrapper).
//! * **`Send + Sync`:** a single [`CryptoVault`] is shareable across threads.
//! * **Envelope isolation (SR-C5):** a wrong `(kek, salt)` context never unwraps
//!   a DEK.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use zeroize::Zeroizing;

use cryptovault::error::CryptoError;
use cryptovault::vault::{generate_dek, generate_salt, CryptoVault};
use cryptovault::{KEY_LEN, SALT_LEN};

// --- AEAD backstop (safety-critical) -----------------------------------------

/// SR-R6: corrupting a valid blob beyond FEC capacity — at several offsets and
/// burst sizes — always yields a typed `Cipher` / `ErrorCorrection` /
/// `InvalidInput` error and **never** a returned plaintext that differs from the
/// original. Even if a mis-decode slips past the RS/Viterbi layers, the AEAD tag
/// is the backstop that rejects it; a silently-wrong `Ok` here would be a
/// critical correctness defect.
#[test]
fn test_sr_r6_aead_backstop_never_returns_wrong_plaintext() {
    let vault = CryptoVault::default();
    let master = [0x24u8; KEY_LEN];
    // A multi-codeword payload so the corruption spans real RS/Viterbi structure.
    let original: Vec<u8> = (0..600u32).map(|i| (i * 7 + 3) as u8).collect();
    let blob = vault.wrap_key(&master, &original).unwrap();
    let raw = STANDARD.decode(&blob).unwrap();

    // Several corruption offsets across the blob, each obliterating a contiguous
    // region far larger than the concatenated code's per-codeword capacity.
    let offsets = [
        0usize,
        raw.len() / 4,
        raw.len() / 2,
        (raw.len() * 3) / 4,
        raw.len().saturating_sub(200),
    ];
    for &off in &offsets {
        for &burst in &[64usize, 200, 400] {
            let mut corrupted = raw.clone();
            let end = (off + burst).min(corrupted.len());
            for b in corrupted.iter_mut().take(end).skip(off) {
                *b ^= 0xFF;
            }
            let result = vault.unwrap_key(&master, &STANDARD.encode(&corrupted));
            match result {
                // The ONLY acceptable Ok is the exact original — which can happen
                // only if the corruption landed within FEC capacity. A differing
                // plaintext would mean the AEAD backstop failed (CRITICAL).
                Ok(pt) => assert_eq!(
                    &*pt,
                    &original[..],
                    "AEAD BACKSTOP VIOLATED: wrong plaintext at offset {off}, burst {burst}"
                ),
                Err(CryptoError::Cipher(_))
                | Err(CryptoError::ErrorCorrection(_))
                | Err(CryptoError::InvalidInput(_)) => {}
                Err(other) => {
                    panic!("unexpected error variant at offset {off}, burst {burst}: {other:?}")
                }
            }
        }
    }
}

/// SR-R6: a heavy, whole-blob corruption (far beyond any correction capacity) is
/// always a typed error — proving the backstop test above is not passing merely
/// because decrypt happens to recover everything.
#[test]
fn test_sr_r6_whole_blob_corruption_is_typed_error() {
    let vault = CryptoVault::default();
    let master = [0x9Au8; KEY_LEN];
    let original: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    let blob = vault.wrap_key(&master, &original).unwrap();
    let mut raw = STANDARD.decode(&blob).unwrap();
    // Flip every byte — nothing survives.
    for b in raw.iter_mut() {
        *b ^= 0xFF;
    }
    let result = vault.unwrap_key(&master, &STANDARD.encode(&raw));
    assert!(
        matches!(
            result,
            Err(CryptoError::Cipher(_))
                | Err(CryptoError::ErrorCorrection(_))
                | Err(CryptoError::InvalidInput(_))
        ),
        "a fully-corrupted blob must fail loud with a typed error, got {result:?}"
    );
}

// --- Zeroize: secret-carrying returns are `Zeroizing` (compile-time) ----------

/// Type-bound sink: only accepts a `Zeroizing<Vec<u8>>`. Passing any other type
/// is a compile error, so calling this on a public return value asserts — at
/// compile time — that the return stays `Zeroizing`-wrapped (SR-C8).
fn require_zeroizing_vec(_secret: Zeroizing<Vec<u8>>) {}

/// Type-bound sink for `Zeroizing<String>` (the UTF-8 decrypt return, SR-C8).
fn require_zeroizing_string(_secret: Zeroizing<String>) {}

/// SR-C8: every secret-carrying return on the public surface is `Zeroizing`
/// (wiped on drop). This test is a **compile-time** assertion — it type-checks
/// only while `derive_key`, `generate_salt`, `generate_dek`, `unwrap_key` return
/// `Zeroizing<Vec<u8>>` and `decrypt_with_key` returns `Zeroizing<String>`.
///
/// Secret *structs* that retain key material (e.g. the interleaver's `CsprngLayer`
/// seed) use a `Zeroizing<[u8; KEY_LEN]>` field — drop-zeroizing, verified in
/// their own module; they are private, so they are asserted at the unit level,
/// not here.
#[test]
fn test_sr_c8_secret_returns_are_zeroizing() {
    let vault = CryptoVault::default();
    let salt = [0u8; SALT_LEN];

    // derive_key → Zeroizing<Vec<u8>>
    let master = vault
        .derive_key("correct horse battery staple", &salt)
        .unwrap();
    require_zeroizing_vec(
        vault
            .derive_key("correct horse battery staple", &salt)
            .unwrap(),
    );

    // generate_salt / generate_dek → Zeroizing<Vec<u8>>
    require_zeroizing_vec(generate_salt().unwrap());
    require_zeroizing_vec(generate_dek().unwrap());

    // unwrap_key → Zeroizing<Vec<u8>>
    let wrapped = vault.wrap_key(&master, b"a data encryption key").unwrap();
    require_zeroizing_vec(vault.unwrap_key(&master, &wrapped).unwrap());

    // decrypt_with_key → Zeroizing<String>
    let blob = vault.encrypt_with_key(&master, "small message").unwrap();
    require_zeroizing_string(vault.decrypt_with_key(&master, &blob).unwrap());
}

// --- Send + Sync --------------------------------------------------------------

/// Compile-time bound: instantiable only for `T: Send + Sync`.
fn assert_send_sync<T: Send + Sync>() {}

/// The vault is immutable after construction (no secret state), so a single
/// instance is `Send + Sync` — a shared vault can encrypt/decrypt concurrently.
#[test]
fn test_cryptovault_is_send_sync() {
    assert_send_sync::<CryptoVault>();
}

// --- Envelope isolation -------------------------------------------------------

/// SR-C5: a DEK wrapped under one KEK never unwraps under a different KEK — the
/// AEAD tag fails with a typed `Cipher` error and no key material is revealed.
#[test]
fn test_sr_c5_wrong_kek_never_unwraps_dek() {
    let vault = CryptoVault::default();
    let kek_a = [0x11u8; KEY_LEN];
    let kek_b = [0x22u8; KEY_LEN];
    let dek: Vec<u8> = (0..64u8).collect();

    let wrapped = vault.wrap_key(&kek_a, &dek).unwrap();

    // Correct KEK recovers the DEK exactly.
    assert_eq!(&*vault.unwrap_key(&kek_a, &wrapped).unwrap(), &dek[..]);

    // Wrong KEK is a typed Cipher error, never the DEK.
    match vault.unwrap_key(&kek_b, &wrapped) {
        Ok(_) => panic!("a wrong KEK must NOT unwrap the DEK"),
        Err(CryptoError::Cipher(_)) => {}
        Err(other) => panic!("wrong KEK: expected Cipher, got {other:?}"),
    }
}

/// SR-C5: the salt is bound as AAD, so a wrong `(kek, salt)` context never
/// re-wraps a DEK. Exercised through the public `rewrap` path: a DEK re-bound to
/// `(kek1, salt1)` re-wraps under the correct old salt but fails with `Cipher`
/// under a wrong old salt — before any re-wrap.
#[test]
fn test_sr_c5_wrong_salt_context_never_unwraps_dek() {
    let vault = CryptoVault::default();
    let kek0 = [0x01u8; KEY_LEN];
    let kek1 = [0x02u8; KEY_LEN];
    let kek2 = [0x03u8; KEY_LEN];
    let salt1 = [0x10u8; SALT_LEN];
    let salt2 = [0x20u8; SALT_LEN];
    let wrong_salt = [0x99u8; SALT_LEN];
    let dek: Vec<u8> = (10..74u8).collect();

    // Bind the DEK into the (kek1, salt1) context via rewrap from a plain wrap
    // (whose bound salt is the empty AAD).
    let wrapped0 = vault.wrap_key(&kek0, &dek).unwrap();
    let bound = vault.rewrap(&kek0, &[], &kek1, &salt1, &wrapped0).unwrap();

    // Correct (kek1, salt1) re-wraps successfully.
    assert!(
        vault.rewrap(&kek1, &salt1, &kek2, &salt2, &bound).is_ok(),
        "the correct (kek, salt) context must re-wrap the DEK"
    );

    // Wrong old salt fails the AEAD tag with Cipher, before any re-wrap.
    match vault.rewrap(&kek1, &wrong_salt, &kek2, &salt2, &bound) {
        Ok(_) => panic!("a wrong salt context must NOT unwrap the DEK"),
        Err(CryptoError::Cipher(_)) => {}
        Err(other) => panic!("wrong salt: expected Cipher, got {other:?}"),
    }
}
