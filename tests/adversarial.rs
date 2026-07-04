// Author: Julian Bolivar
// Version: 0.2.1
// Date: 2026-07-03
//! Task 20c — adversarial corpus (CERTIFICATION BAR, SR-R3 / SR-R4 / SR-R5 / SR-R6).
//!
//! A table of hand-crafted hostile inputs, each fed through the public raw-byte
//! decrypt door ([`CryptoVault::unwrap_key`]) under a valid 32-byte master. Every
//! case MUST return a **typed [`CryptoError`]** — never a panic, never an
//! unbounded allocation, never a silently-accepted `Ok`. The corpus covers the
//! full decrypt-path guard ladder:
//!
//! * truncated base64 (lengths 0..5),
//! * an oversized base64 string (`> MAX_B64_LEN`) rejected **before** decode
//!   allocates (SR-R4 pre-allocation DoS guard),
//! * an oversized decoded blob (`> MAX_BLOB_LEN`) and its `+1` off-by-one,
//! * a body whose length is not a valid chunked-Viterbi frame (SR-R3a),
//! * all-`0x00` / all-`0xFF` junk,
//! * non-canonical base64 as three distinct vectors — bad alphabet, bad padding,
//!   trailing bits (SR-F6).
//!
//! The crafted bad-`version` and oversized-`plaintext_len` vectors (which need
//! the crate-private blob wire layer, L4) are covered by the `src/blob.rs`
//! `full_path_crafted_tests` unit tests instead.
//!
//! These run against the fully-implemented API and are expected to PASS; a panic
//! or a wrong-variant / `Ok` result would surface a real defect.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use cryptovault::error::CryptoError;
use cryptovault::vault::CryptoVault;
use cryptovault::{KEY_LEN, MAX_B64_LEN, MAX_BLOB_LEN};

/// A valid 32-byte master to drive the decrypt path — the hostility is entirely
/// in the ciphertext argument, not the key.
const MASTER: [u8; KEY_LEN] = [0x42u8; KEY_LEN];

/// The typed-error family a case is allowed to surface (a compact projection of
/// [`CryptoError`] used to assert the *variant*, ignoring the message string).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Variant {
    Cipher,
    ErrorCorrection,
    Encoding,
    InvalidInput,
}

/// Projects a [`CryptoError`] onto its [`Variant`] tag for table assertions.
fn variant_of(e: &CryptoError) -> Variant {
    match e {
        CryptoError::KeyDerivation(_) => {
            // No adversarial *ciphertext* can reach the KDF path (Argon2 runs only
            // in derive_key), so this is never expected from the corpus.
            unreachable!("decrypt path never surfaces a KeyDerivation error")
        }
        CryptoError::Cipher(_) => Variant::Cipher,
        CryptoError::ErrorCorrection(_) => Variant::ErrorCorrection,
        CryptoError::Encoding(_) => Variant::Encoding,
        CryptoError::InvalidInput(_) => Variant::InvalidInput,
    }
}

/// One adversarial vector: a name, the base64 string fed to `unwrap_key`, and the
/// set of typed-error variants that count as a correct rejection.
struct Case {
    name: &'static str,
    input: String,
    allowed: &'static [Variant],
}

/// Builds the small-payload adversarial corpus (the heavy ~megabyte vectors live
/// in their own tests to bound peak memory per case).
fn small_corpus() -> Vec<Case> {
    let mut cases = Vec::new();

    // Truncated base64: lengths 0..5. Depending on base64 length rules each is
    // either a decode error (non-multiple-of-4 length) or decodes to too-few
    // bytes for even one RS codeword — both are correct typed rejections.
    for s in ["", "A", "AB", "ABC", "ABCD"] {
        cases.push(Case {
            name: "truncated",
            input: s.to_string(),
            allowed: &[Variant::Encoding, Variant::InvalidInput],
        });
    }

    // (The crafted bad-version and oversized-`plaintext_len` vectors, which need
    // the crate-private blob wire layer, are covered by the `src/blob.rs`
    // `full_path_crafted_tests` unit tests — L4.)

    // A body length that cannot be a `2·L + 2` chunked-Viterbi frame (odd) — the
    // pre-FEC structural gate rejects it (SR-R3a), never a panic.
    cases.push(Case {
        name: "non_chunked_viterbi_length",
        input: STANDARD.encode(vec![0u8; 203]),
        allowed: &[Variant::InvalidInput],
    });

    // All-zero / all-ones junk of a length that *passes* the pre-FEC frame gate
    // (512 = 2·255 + 2 ⇒ L = 255, one codeword) so it drives the deeper FEC/AEAD
    // path; recovery to a valid header is cryptographically impossible → typed
    // error, never Ok.
    cases.push(Case {
        name: "all_zero",
        input: STANDARD.encode(vec![0x00u8; 512]),
        allowed: &[
            Variant::InvalidInput,
            Variant::ErrorCorrection,
            Variant::Cipher,
        ],
    });
    cases.push(Case {
        name: "all_ones",
        input: STANDARD.encode(vec![0xFFu8; 512]),
        allowed: &[
            Variant::InvalidInput,
            Variant::ErrorCorrection,
            Variant::Cipher,
        ],
    });

    // Non-canonical base64 — three distinct failure modes, each rejected by the
    // strict STANDARD engine with an Encoding error (SR-F6).
    cases.push(Case {
        // '@' is outside the standard base64 alphabet.
        name: "non_canonical_bad_alphabet",
        input: "@@@@".to_string(),
        allowed: &[Variant::Encoding],
    });
    cases.push(Case {
        // Length 7 (not a multiple of 4) with a stray pad → invalid padding.
        name: "non_canonical_bad_padding",
        input: "YWJjZA=".to_string(),
        allowed: &[Variant::Encoding],
    });
    cases.push(Case {
        // "AB==" decodes to 1 byte but 'B' carries non-zero discarded (trailing)
        // bits; the strict engine rejects it (decode_allow_trailing_bits = false).
        name: "non_canonical_trailing_bits",
        input: "AB==".to_string(),
        allowed: &[Variant::Encoding],
    });

    cases
}

/// SR-R3 / SR-R5 / SR-R6: every small hand-crafted hostile input is rejected with
/// a typed error of the expected variant — no panic, no `Ok`.
#[test]
fn test_sr_r5_small_adversarial_corpus_is_typed_error_no_panic() {
    let vault = CryptoVault::default();
    for case in small_corpus() {
        match vault.unwrap_key(&MASTER, &[], &case.input) {
            Ok(_) => panic!(
                "adversarial case '{}' unexpectedly returned Ok (input len {})",
                case.name,
                case.input.len()
            ),
            Err(e) => {
                let v = variant_of(&e);
                assert!(
                    case.allowed.contains(&v),
                    "adversarial case '{}' returned {:?} ({e}), allowed {:?}",
                    case.name,
                    v,
                    case.allowed
                );
            }
        }
    }
}

/// SR-R4: a base64 string longer than `MAX_B64_LEN` is rejected with
/// `InvalidInput` **before** base64-decode allocates — the pre-allocation DoS
/// guard runs first (kept in its own test to bound peak memory).
#[test]
fn test_sr_r4_oversized_base64_string_rejected_pre_allocation() {
    let vault = CryptoVault::default();
    let giant = "A".repeat(MAX_B64_LEN + 1);
    assert!(
        matches!(
            vault.unwrap_key(&MASTER, &[], &giant),
            Err(CryptoError::InvalidInput(_))
        ),
        "an over-cap base64 string must be rejected pre-allocation with InvalidInput"
    );
}

/// SR-R4: a base64 string that *decodes* to more than `MAX_BLOB_LEN` bytes (while
/// staying within the base64-length cap) is rejected with `InvalidInput` by the
/// decoded-length guard, never over-allocated into the FEC decode.
#[test]
fn test_sr_r4_oversized_decoded_blob_rejected() {
    let vault = CryptoVault::default();
    let oversized = STANDARD.encode(vec![0u8; MAX_BLOB_LEN + 1000]);
    assert!(
        matches!(
            vault.unwrap_key(&MASTER, &[], &oversized),
            Err(CryptoError::InvalidInput(_))
        ),
        "a decoded blob past MAX_BLOB_LEN must be rejected with InvalidInput"
    );
}

/// SR-R7: decode-path failures carry a fixed, **generic** message that leaks no
/// structural oracle — no exact lengths/offsets (digits) and no FEC-crate-internal
/// vocabulary (Reed-Solomon codeword counts, RS-stream lengths, Viterbi framing).
/// An attacker probing malformed blobs learns only the failing *stage* (the typed
/// variant is deliberately kept), never a structural specific.
#[test]
fn test_sr_r7_decode_errors_carry_no_structural_detail() {
    let vault = CryptoVault::default();
    // Malformed blobs whose rejection originates on the FEC / blob decode path
    // (chunked-Viterbi framing, RS-stream framing, and the recovered-header
    // version check) — each historically embedded exact lengths or FEC wording.
    let malformed: [Vec<u8>; 3] = [
        vec![0u8; 203],    // odd body → invalid chunked-Viterbi frame
        vec![0u8; 202],    // valid frame, derived RS-stream length is no codeword multiple
        vec![0x00u8; 512], // clean frame → all-zero RS codeword → bad recovered version
    ];
    // Substrings that would betray FEC/structural internals to a probing attacker.
    const BANNED_WORDS: [&str; 6] = ["255", "codeword", "rs-stream", "viterbi", "reed", "chunk"];
    for blob in malformed {
        let b64 = STANDARD.encode(&blob);
        let err = vault
            .unwrap_key(&MASTER, &[], &b64)
            .expect_err("a malformed blob must be rejected");
        let msg = err.to_string();
        let lower = msg.to_lowercase();
        assert!(
            !msg.chars().any(|c| c.is_ascii_digit()),
            "decode error must not embed any length/offset digit, got: {msg}"
        );
        for banned in BANNED_WORDS {
            assert!(
                !lower.contains(banned),
                "decode error must not leak FEC-internal term '{banned}', got: {msg}"
            );
        }
    }
    // Malformed base64 (bad alphabet, bad padding, trailing bits): the strict
    // STANDARD engine rejects each, but the crate's error MUST NOT echo the
    // base64 library's interpolated byte-index / offset detail — same fixed,
    // generic message contract as the FEC decode path above.
    let bad_base64: [&str; 3] = [
        "@@@@",    // bad alphabet — '@' outside the standard base64 set
        "YWJjZA=", // bad padding — length 7 with a stray pad
        "AB==",    // trailing bits — 'B' carries non-zero discarded bits
    ];
    for b64 in bad_base64 {
        let err = vault
            .unwrap_key(&MASTER, &[], b64)
            .expect_err("a malformed base64 input must be rejected");
        let msg = err.to_string();
        let lower = msg.to_lowercase();
        assert!(
            !msg.chars().any(|c| c.is_ascii_digit()),
            "base64 decode error must not embed any byte-index/offset digit, got: {msg}"
        );
        for banned in BANNED_WORDS {
            assert!(
                !lower.contains(banned),
                "base64 decode error must not leak internal term '{banned}', got: {msg}"
            );
        }
    }
}

/// SR-R4: the off-by-one boundary — a decoded blob of exactly `MAX_BLOB_LEN + 1`
/// bytes is rejected (the cap is a strict `>`), never a panic or over-allocation.
#[test]
fn test_sr_r4_off_by_one_over_max_blob_len_rejected() {
    let vault = CryptoVault::default();
    let off_by_one = STANDARD.encode(vec![0u8; MAX_BLOB_LEN + 1]);
    assert!(
        matches!(
            vault.unwrap_key(&MASTER, &[], &off_by_one),
            Err(CryptoError::InvalidInput(_))
        ),
        "a decoded blob of MAX_BLOB_LEN + 1 bytes must be rejected with InvalidInput"
    );
}
