// Author: Julian Bolivar
// Version: 0.2.0
// Date: 2026-07-03
//! Task 20b — property-based suite (`proptest`, CERTIFICATION BAR).
//!
//! Over thousands of arbitrary inputs, exercises the crate's reversible and
//! total public operations through the raw-byte envelope door
//! (`wrap_key`/`unwrap_key`) — the front door that accepts arbitrary bytes:
//!
//! * `pt_encrypt_decrypt_roundtrip` — `decrypt(encrypt(pt)) == pt` for any bytes.
//! * `pt_decrypt_never_panics` — arbitrary base64 + arbitrary key always
//!   **returns** (`Ok`/`Err`), never panics, never over-allocates (SR-R5).
//! * `pt_wrong_key_never_wrong_plaintext` — a wrong key is always `Err`, never a
//!   silently-wrong plaintext (the AEAD is the integrity anchor, SR-R6).
//! * `pt_noisy_channel_within_capacity` — a bounded channel burst inside FEC
//!   capacity is corrected (SR-F*).
//!
//! ## Key material & speed
//!
//! `wrap_key`/`unwrap_key` accept the master directly (HKDF-expanded internally),
//! so these properties feed a random 32-byte master rather than running Argon2
//! per case — 2048 memory-hard derivations would take hours and add no coverage
//! the dedicated Argon2 unit/scenario tests do not already provide. Payload
//! bounds are capped so the whole suite finishes in the minutes range.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use proptest::prelude::*;

use cryptovault::error::CryptoError;
use cryptovault::vault::CryptoVault;

/// Upper bound on `pt_encrypt_decrypt_roundtrip` (and wrong-key) payloads.
///
/// **Reduced from the plan's `100_000`-byte ceiling to `2 KiB`** so that `2048`
/// cases × a full AEAD+FEC round-trip complete in the minutes range, not hours
/// (documented per the task's "you may reduce the upper payload bound"). `2 KiB`
/// still spans **9+** RS(255,223) codewords, so the multi-chunk RS/interleaver/
/// Viterbi paths and every sub-223-byte boundary are exercised across the run;
/// the single 10 MiB extreme is covered by the ignored scenario test.
const ROUNDTRIP_MAX_LEN: usize = 2 * 1024;

/// Upper bound on the arbitrary-bytes fed to `pt_decrypt_never_panics`.
///
/// Large enough to exceed a single RS/Viterbi chunk and to probe the
/// oversized-input guards, bounded so base64-encoding 2048 samples stays fast.
const FUZZBYTES_MAX_LEN: usize = 8 * 1024;

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    /// SC-1 / SR-R1: `unwrap_key(wrap_key(pt)) == pt` for arbitrary payload bytes
    /// and an arbitrary 32-byte master — the reversible core round-trips exactly.
    #[test]
    fn pt_encrypt_decrypt_roundtrip(
        pt in proptest::collection::vec(any::<u8>(), 0..ROUNDTRIP_MAX_LEN),
        key in proptest::array::uniform32(any::<u8>()),
    ) {
        let v = CryptoVault::default();
        let blob = v.wrap_key(&key, &[], &pt).unwrap();
        let recovered = v.unwrap_key(&key, &[], &blob).unwrap();
        prop_assert_eq!(&*recovered, &pt[..]);
    }

    /// SC-6 / SR-R5: the decrypt path is **total** — arbitrary bytes (base64-wrapped)
    /// under an arbitrary key always return a typed `Result`, never panic, never
    /// over-allocate.
    #[test]
    fn pt_decrypt_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..FUZZBYTES_MAX_LEN),
        key in proptest::array::uniform32(any::<u8>()),
    ) {
        let v = CryptoVault::default();
        // Must RETURN (Ok or Err), never panic.
        let _ = v.unwrap_key(&key, &[], &STANDARD.encode(&bytes));
    }

    /// SC-5 / SR-R6: with `k1 != k2`, decrypting under `k2` is **always** `Err` —
    /// a wrong key never yields a silently-wrong (or the correct) plaintext.
    #[test]
    fn pt_wrong_key_never_wrong_plaintext(
        pt in proptest::collection::vec(any::<u8>(), 0..ROUNDTRIP_MAX_LEN),
        k1 in proptest::array::uniform32(any::<u8>()),
        k2 in proptest::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(k1 != k2);
        let v = CryptoVault::default();
        let blob = v.wrap_key(&k1, &[], &pt).unwrap();
        match v.unwrap_key(&k2, &[], &blob) {
            Ok(wrong) => prop_assert!(false, "wrong key decrypted to {} bytes", wrong.len()),
            Err(CryptoError::Cipher(_)) => {}
            Err(other) => prop_assert!(
                false,
                "wrong key must fail with Cipher, got {:?}",
                other
            ),
        }
    }

    /// SC-2 / SR-F*: a bounded contiguous burst (≤ 16 symbols) injected into the
    /// Viterbi-encoded blob of a small payload is corrected by the concatenated
    /// FEC — the exact payload is recovered and the AEAD tag verifies.
    #[test]
    fn pt_noisy_channel_within_capacity(
        pt in proptest::collection::vec(any::<u8>(), 1..256usize),
        key in proptest::array::uniform32(any::<u8>()),
        burst in 1usize..=16,
        offset_frac in 0.1f64..0.8,
    ) {
        let v = CryptoVault::default();
        let blob = v.wrap_key(&key, &[], &pt).unwrap();
        let mut raw = STANDARD.decode(&blob).unwrap();
        let start = ((raw.len() as f64) * offset_frac) as usize;
        let end = (start + burst).min(raw.len());
        for b in raw.iter_mut().take(end).skip(start) {
            *b ^= 0xFF;
        }
        let corrupted = STANDARD.encode(&raw);
        let recovered = v.unwrap_key(&key, &[], &corrupted).unwrap();
        prop_assert_eq!(&*recovered, &pt[..]);
    }
}
