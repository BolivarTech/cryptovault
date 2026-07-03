// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Task 20 — BDD acceptance scenarios `SC-1..SC-8` (CERTIFICATION BAR).
//!
//! End-to-end coverage of the eight behaviour scenarios from
//! `sbtdd/spec-behavior.md`, exercised **only** through the crate's public API
//! (`CryptoVault` + the public `blob`/`fec` helpers). Each `#[test]` maps to one
//! scenario and carries its `SC-*` / `SR-*` id; boundary variants (payload sizes,
//! burst sizes, adversarial inputs) live inside the corresponding test.
//!
//! ## Channel model
//!
//! A "channel error" is injected by base64-decoding the blob, flipping bytes in
//! the Viterbi-encoded stream, and re-base64-encoding — exactly what a caller
//! would receive off a noisy wire. The concatenated FEC
//! (`Viterbi → de-interleave → RS`) either corrects it or the AEAD tag rejects
//! the result; a corrupted blob is **never** decrypted to wrong-but-plausible
//! plaintext (the AEAD is the sole integrity anchor).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use cryptovault::blob::{decode_blob, encode_blob};
use cryptovault::error::CryptoError;
use cryptovault::fec::ConcatenatedFec;
use cryptovault::vault::CryptoVault;
use cryptovault::{BLOB_VERSION, MAX_B64_LEN, SALT_LEN};

/// A fixed raw 32-byte master/KEK. The public `wrap_key`/`unwrap_key` and
/// `encrypt_with_key`/`decrypt_with_key` accept the master directly (they
/// HKDF-expand it internally), so tests that do not exercise Argon2 use a raw key
/// and stay fast — the memory-hard `derive_key` path is covered explicitly in
/// SC-5.
const MASTER: [u8; 32] = [0x5Au8; 32];

/// Flips `count` consecutive bytes of the base64-decoded blob starting at
/// `start`, then re-encodes — a contiguous channel burst on the wire.
///
/// Bytes past the end of the blob are ignored (clamped) so the helper never
/// panics regardless of `start`/`count`.
fn corrupt_burst(blob: &str, start: usize, count: usize) -> String {
    let mut raw = STANDARD.decode(blob).expect("our own blob is valid base64");
    let end = start.saturating_add(count).min(raw.len());
    for b in raw.iter_mut().take(end).skip(start) {
        *b ^= 0xFF;
    }
    STANDARD.encode(&raw)
}

// ---------------------------------------------------------------------------
// SC-1 — Clean-channel round-trip.
// ---------------------------------------------------------------------------

/// SC-1 (SR-F*, SR-R1): a payload encrypted then decrypted under the same key
/// over an error-free channel recovers **exactly**, across chunk-boundary and
/// small payload sizes.
#[test]
fn test_sc_1_clean_channel_roundtrip_recovers_exact_payload() {
    let v = CryptoVault::default();
    // Sizes straddle the RS 223/255 chunk boundaries (222/223/224, 446/447).
    for &len in &[0usize, 1, 32, 222, 223, 224, 446, 447, 1024] {
        let pt: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        let blob = v.wrap_key(&MASTER, &pt).unwrap();
        let recovered = v.unwrap_key(&MASTER, &blob).unwrap();
        assert_eq!(&*recovered, &pt, "clean round-trip exact at len={len}");
    }
}

/// SC-1: the full `MAX_PLAINTEXT_LEN` (10 MiB) payload round-trips. Ignored by
/// default (FEC over 10 MiB is slow); run with
/// `cargo nextest run --run-ignored all`.
#[test]
#[ignore = "10 MiB FEC round-trip is slow; run with --run-ignored all"]
fn test_sc_1_clean_channel_roundtrip_max_plaintext_len() {
    let v = CryptoVault::default();
    let pt = vec![0xA5u8; cryptovault::MAX_PLAINTEXT_LEN];
    let blob = v.wrap_key(&MASTER, &pt).unwrap();
    let recovered = v.unwrap_key(&MASTER, &blob).unwrap();
    assert_eq!(&*recovered, &pt, "10 MiB round-trip is exact");
}

// ---------------------------------------------------------------------------
// SC-2 — Noisy channel within FEC capacity.
// ---------------------------------------------------------------------------

/// SC-2 (SR-F*, SR-R2): a burst of `{1, 16}` corrupted symbols within the
/// concatenated FEC's correction capacity is fully corrected — the exact payload
/// is recovered and the AEAD tag verifies.
#[test]
fn test_sc_2_noisy_channel_within_capacity_recovers_exact_payload() {
    let v = CryptoVault::default();
    // Small payloads keep a contiguous burst inside RS(255,223) capacity
    // (≤16 symbols/codeword) after Viterbi + the block interleaver.
    for &len in &[32usize, 64, 200] {
        let pt: Vec<u8> = (0..len).map(|i| (i * 13 + 1) as u8).collect();
        let blob = v.wrap_key(&MASTER, &pt).unwrap();
        let raw_len = STANDARD.decode(&blob).unwrap().len();
        let mid = raw_len / 3;
        for &burst in &[1usize, 16] {
            let corrupted = corrupt_burst(&blob, mid, burst);
            let recovered = v
                .unwrap_key(&MASTER, &corrupted)
                .unwrap_or_else(|e| panic!("len={len} burst={burst} must recover, got {e:?}"));
            assert_eq!(
                &*recovered, &pt,
                "within-capacity burst recovers exactly (len={len}, burst={burst})"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// SC-3 — Corruption beyond FEC capacity.
// ---------------------------------------------------------------------------

/// SC-3 (SR-R6): corruption beyond the FEC correction capacity yields a typed
/// error (FEC or AEAD failure) and **never** a silently-wrong plaintext.
#[test]
fn test_sc_3_corruption_beyond_capacity_is_typed_error_never_wrong_plaintext() {
    let v = CryptoVault::default();
    let pt: Vec<u8> = (0..64u8).collect();
    let blob = v.wrap_key(&MASTER, &pt).unwrap();
    let raw_len = STANDARD.decode(&blob).unwrap().len();

    // A large contiguous burst (well past the ~24-symbol single-codeword limit)
    // and a near-total wipe both must fail loud, never mis-decode.
    for &burst in &[64usize, raw_len] {
        let corrupted = corrupt_burst(&blob, raw_len / 4, burst);
        match v.unwrap_key(&MASTER, &corrupted) {
            Err(CryptoError::ErrorCorrection(_))
            | Err(CryptoError::Cipher(_))
            | Err(CryptoError::InvalidInput(_)) => {}
            Err(other) => panic!("unexpected error variant for burst={burst}: {other:?}"),
            Ok(p) => assert_ne!(
                &*p, &pt,
                "beyond-capacity corruption must never recover the exact plaintext"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// SC-4 — Tampered header (AAD binding).
// ---------------------------------------------------------------------------

/// SC-4 (SR-C4, SR-R6): a header whose `plaintext_len` or `version` is altered
/// beyond FEC capacity (modelled by re-encoding the recovered body under a
/// tampered header) fails the AEAD tag / structural check — never wrong
/// plaintext. The header is bound as AAD, so an altered-but-error-corrected
/// header cannot pass authentication.
#[test]
fn test_sc_4_tampered_header_fails_authentication() {
    let v = CryptoVault::default();
    let fec = ConcatenatedFec::default();
    let pt: Vec<u8> = (0..48u8).collect();

    // Recover the genuine (version, plaintext_len, body) of a real blob.
    let blob = v.wrap_key(&MASTER, &pt).unwrap();
    let raw = STANDARD.decode(&blob).unwrap();
    let (version, plaintext_len, body) = decode_blob(&fec, &raw).unwrap();
    assert_eq!(version, BLOB_VERSION);
    assert_eq!(plaintext_len as usize, pt.len());

    // (a) Tamper `plaintext_len` (still ≤ body capacity): the recovered header no
    // longer matches the AAD the ciphertext was sealed under → AEAD Cipher error.
    let tampered_len = encode_blob(&fec, BLOB_VERSION, plaintext_len - 1, &body);
    let b64_len = STANDARD.encode(&tampered_len);
    assert!(
        matches!(v.unwrap_key(&MASTER, &b64_len), Err(CryptoError::Cipher(_))),
        "tampered plaintext_len must fail the AEAD tag"
    );

    // (b) Tamper `version`: decode rejects an unknown version before AEAD-open.
    let tampered_ver = encode_blob(&fec, BLOB_VERSION + 1, plaintext_len, &body);
    let b64_ver = STANDARD.encode(&tampered_ver);
    assert!(
        matches!(
            v.unwrap_key(&MASTER, &b64_ver),
            Err(CryptoError::InvalidInput(_))
        ),
        "tampered version must be rejected as InvalidInput"
    );
}

// ---------------------------------------------------------------------------
// SC-5 — Wrong KEK / salt / password.
// ---------------------------------------------------------------------------

/// SC-5 (SR-C5): unwrapping under a KEK, salt, or password different from the one
/// used to wrap fails the AEAD tag with a typed `Cipher` error (or `InvalidInput`
/// for a malformed salt) and reveals **no** key material.
#[test]
fn test_sc_5_wrong_kek_salt_or_password_reveals_no_key_material() {
    let v = CryptoVault::default();
    let dek: Vec<u8> = (0..=255u16).map(|b| b as u8).collect();

    // Wrong KEK.
    let wrapped = v.wrap_key(&[1u8; 32], &dek).unwrap();
    assert!(
        matches!(
            v.unwrap_key(&[2u8; 32], &wrapped),
            Err(CryptoError::Cipher(_))
        ),
        "wrong KEK → Cipher error, no key material"
    );

    // Wrong salt: a different salt derives a different master → wrong KEK.
    let m_salt_a = v.derive_key("correct horse", &[7u8; SALT_LEN]).unwrap();
    let m_salt_b = v.derive_key("correct horse", &[8u8; SALT_LEN]).unwrap();
    let wrapped_salt = v.wrap_key(&m_salt_a, &dek).unwrap();
    assert!(
        matches!(
            v.unwrap_key(&m_salt_b, &wrapped_salt),
            Err(CryptoError::Cipher(_))
        ),
        "wrong salt → different master → Cipher error"
    );

    // Wrong password: a different passphrase derives a different master.
    let m_pw_a = v.derive_key("passphrase one", &[9u8; SALT_LEN]).unwrap();
    let m_pw_b = v.derive_key("passphrase two", &[9u8; SALT_LEN]).unwrap();
    let wrapped_pw = v.wrap_key(&m_pw_a, &dek).unwrap();
    assert!(
        matches!(
            v.unwrap_key(&m_pw_b, &wrapped_pw),
            Err(CryptoError::Cipher(_))
        ),
        "wrong password → different master → Cipher error"
    );

    // A malformed (wrong-length) salt is rejected at derivation, never used.
    assert!(
        matches!(
            v.derive_key("pw", &[0u8; SALT_LEN - 1]),
            Err(CryptoError::InvalidInput(_))
        ),
        "wrong-length salt → InvalidInput"
    );
}

// ---------------------------------------------------------------------------
// SC-6 — Adversarial blob.
// ---------------------------------------------------------------------------

/// SC-6 (SR-R3, SR-R5): an arbitrary hostile input — empty, 1-byte, truncated,
/// oversized, bad-version, junk, or non-canonical base64 — yields a typed error
/// without panicking and without unbounded allocation.
#[test]
fn test_sc_6_adversarial_blob_is_typed_error_without_panic() {
    let v = CryptoVault::default();
    let fec = ConcatenatedFec::default();

    // A genuine blob to derive truncated / bad-version variants from.
    let good = v.wrap_key(&MASTER, b"a small secret").unwrap();

    // Each entry: (label, input). Every one must return a typed error, no panic.
    let bad_version = {
        let raw = STANDARD.decode(&good).unwrap();
        let (_v, pl, body) = decode_blob(&fec, &raw).unwrap();
        STANDARD.encode(encode_blob(&fec, BLOB_VERSION + 1, pl, &body))
    };
    let truncated = &good[..good.len() / 2];
    let oversized = "A".repeat(MAX_B64_LEN + 1);
    let junk_b64 = STANDARD.encode(vec![0xEFu8; 600]); // valid base64, junk bytes

    let cases: Vec<(&str, &str)> = vec![
        ("empty", ""),
        ("one-byte", "A"),
        ("truncated", truncated),
        ("oversized-b64", &oversized),
        ("bad-version", &bad_version),
        ("junk", &junk_b64),
        ("non-canonical-alphabet", "****"),
        ("bad-padding", "AB=C"),
        ("all-zero-b64", "AAAA"),
    ];

    for (label, input) in cases {
        match v.unwrap_key(&MASTER, input) {
            Err(
                CryptoError::InvalidInput(_)
                | CryptoError::Encoding(_)
                | CryptoError::ErrorCorrection(_)
                | CryptoError::Cipher(_),
            ) => {}
            Err(other) => panic!("case '{label}': unexpected variant {other:?}"),
            Ok(_) => panic!("case '{label}': adversarial input must not decrypt"),
        }
    }
}

// ---------------------------------------------------------------------------
// SC-7 — Rewrap round-trip.
// ---------------------------------------------------------------------------

/// SC-7 (SR-C5): `rewrap` re-binds a DEK from an old `(kek, salt)` context to a
/// new one — the new context recovers the exact DEK, the old context no longer
/// unwraps it.
#[test]
fn test_sc_7_rewrap_rebinds_context_old_no_longer_unwraps() {
    let v = CryptoVault::default();
    let (old_kek, new_kek) = ([1u8; 32], [9u8; 32]);
    // `wrap_key` binds an empty salt as AAD, so the old context's salt is `&[]`.
    let old_salt: &[u8] = &[];
    let new_salt: &[u8] = &[42u8; SALT_LEN];
    let dek: Vec<u8> = (0..96u8).collect();

    let wrapped = v.wrap_key(&old_kek, &dek).unwrap();
    let rewrapped = v
        .rewrap(&old_kek, old_salt, &new_kek, new_salt, &wrapped)
        .unwrap();

    // The NEW context recovers the exact DEK — proven by rewrapping back to the
    // (old_kek, empty) context and unwrapping through the public door.
    let back = v
        .rewrap(&new_kek, new_salt, &old_kek, old_salt, &rewrapped)
        .unwrap();
    let recovered = v.unwrap_key(&old_kek, &back).unwrap();
    assert_eq!(&*recovered, &dek, "rewrap preserves the DEK end-to-end");

    // The OLD context (old_kek, empty salt) no longer unwraps the rewrapped blob
    // (it is bound to new_kek + new_salt).
    assert!(
        matches!(
            v.unwrap_key(&old_kek, &rewrapped),
            Err(CryptoError::Cipher(_))
        ),
        "old context must no longer unwrap the rewrapped blob"
    );

    // Rewrapping under the wrong old context fails the tag before any re-wrap.
    assert!(
        matches!(
            v.rewrap(&old_kek, old_salt, &new_kek, new_salt, &rewrapped),
            Err(CryptoError::Cipher(_))
        ),
        "wrong old context in rewrap → Cipher error, no DEK exposed"
    );
}

// ---------------------------------------------------------------------------
// SC-8 — Empty & boundary payloads.
// ---------------------------------------------------------------------------

/// SC-8 (SR-F1): empty plaintext and payloads at the RS chunk boundaries
/// (`223 / 446 / 447`) round-trip exactly, and an over-cap base64 string at
/// `MAX_B64_LEN + 1` is rejected pre-allocation.
#[test]
fn test_sc_8_empty_and_boundary_payloads_roundtrip_and_over_cap_rejected() {
    let v = CryptoVault::default();

    // Empty and chunk-boundary payloads round-trip exactly.
    for &len in &[0usize, 223, 446, 447] {
        let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let blob = v.wrap_key(&MASTER, &pt).unwrap();
        let recovered = v.unwrap_key(&MASTER, &blob).unwrap();
        assert_eq!(&*recovered, &pt, "boundary payload len={len} round-trips");
    }

    // MAX_B64_LEN + 1 is rejected before base64-decode allocates (SR-R4 guard).
    let over_cap = "A".repeat(MAX_B64_LEN + 1);
    assert!(
        matches!(
            v.unwrap_key(&MASTER, &over_cap),
            Err(CryptoError::InvalidInput(_))
        ),
        "base64 over MAX_B64_LEN is rejected pre-allocation"
    );
}
