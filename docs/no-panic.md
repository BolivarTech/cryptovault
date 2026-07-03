# No-Panic Audit — decrypt / unwrap path (SR-R5, P0-4)

**Author:** Julian Bolivar · **Version:** 1.0.0 · **Date:** 2026-07-03

This is the **formal half** of the SR-R5 no-panic guarantee (Task 21): an
enumeration of every FEC / decrypt entry point reachable from adversarial input,
each mapped to the structural-validation gate that bounds it *before* an
early-stage codec or an allocation can run. The **empirical half** is the
`cargo-fuzz` demonstration (below) plus the in-suite `proptest`
`pt_decrypt_never_panics` (2048 arbitrary cases). Together they discharge
SR-R5 under **both** `panic="unwind"` and `panic="abort"` — no reliance on
`catch_unwind`.

> Scope: `#![forbid(unsafe_code)]` holds crate-wide, and both FEC crates
> (`reedsolomon` 0.1.0, `viterbi` 0.0.1) are pure-Rust `forbid(unsafe)`, so the
> boundary risk is **panic-only, never UB**. This table is the artifact Task 25's
> external reviewer audits line-by-line.

## Reachability

The two public decrypt doors both funnel into one byte core:

```
decrypt_with_key(key, &str) ─┐
                             ├─▶ decrypt_bytes_aad(master, b64, aad) ─▶ decode_blob ─▶ ConcatenatedFec::decode
unwrap_key(kek, &str) ───────┘                                                          ├─ ViterbiCodec::decode
rewrap(...) ─── (unwrap then wrap) ──────────────────────────────────────────────────  ├─ Interleaver::deinterleave
                                                                                        └─ ReedSolomonCodec::decode
```

`rewrap` reaches the same core via `unwrap`, so it inherits every gate below.

## Entry point → guarding gate

| # | Entry point (function) | Adversary-controlled input | Structural gate that bounds it | Failure mode on hostile input |
|---|------------------------|----------------------------|--------------------------------|-------------------------------|
| 1 | `CryptoVault::decrypt_bytes_aad` — base64 length cap | `b64: &str` length | `b64.len() > MAX_B64_LEN` → reject **before** base64 alloc (SR-R4) | `CryptoError::InvalidInput` |
| 2 | `base64::STANDARD.decode` | base64 alphabet / padding / trailing bits | strict `STANDARD` engine rejects non-canonical input | `CryptoError::Encoding` |
| 3 | `blob::validate_pre_fec` — DoS cap | decoded blob length | `received.len() > MAX_BLOB_LEN` → reject before any FEC alloc (SR-R4) | `CryptoError::InvalidInput` |
| 4 | `blob::validate_pre_fec` — framing | decoded blob length | `rs_len_from_body` (shared chunk math) requires even, `≥ MIN_CHUNK_BODY` final sub-block; derived `L` a positive multiple of `RS_BLOCK` (SR-R3a / P0-6) | `CryptoError::InvalidInput` |
| 5 | `ViterbiCodec::decode` — chunk split | blob body length | `chunk_body_lengths` re-validates each sub-block length before the codec runs; empty → empty (early return) | `CryptoError::InvalidInput` |
| 6 | `viterbi::CcsdsViterbiDecoder::decode_block` | coded bytes + `nbits` | `nbits = coded_nbits(body_len)` derived from the **validated** even body length; decoder cap `max_info_bits = VITERBI_CHUNK*8 ≤ 1_000_000`; typed `DecodeError` mapped, never propagated raw | `CryptoError::InvalidInput` / `ErrorCorrection` |
| 7 | `ConcatenatedFec::decode` — length cross-check | post-Viterbi RS-stream length | SR-R3b: `rs_stream.len() != l` (the pre-FEC-derived length) → reject (catches a codec length bug) | `CryptoError::InvalidInput` |
| 8 | `Interleaver::deinterleave` | RS-stream bytes | operates on the exact validated byte count (any length N, no divisibility/padding assumption); permutation table is `O(I×RS_BLOCK)` transient, bounded | infallible (no indexing past `N`) |
| 9 | `ReedSolomonCodec::decode` | RS-stream bytes + `pre_len` | length re-checked a whole multiple of `RS_BLOCK` before the crate runs; `RsError` mapped to typed error | `CryptoError::InvalidInput` / `ErrorCorrection` |
| 10 | `blob::decode_blob` — header read | recovered protected payload | length-guarded header read (`protected.len() < HEADER_LEN` → error); `version != BLOB_VERSION` → error; `plaintext_len > MAX_PLAINTEXT_LEN` → error; derived `protected_len > protected.len()` → error (SR-R6, all before any slice) | `CryptoError::InvalidInput` |
| 11 | `decrypt_bytes_aad` — body split | recovered body length | `body.len() < NONCE_LEN` → error before `split_at` (defensive; `decode_blob` already guarantees it) | `CryptoError::InvalidInput` |
| 12 | `AuthenticatedCipher::decrypt` (AES-256-GCM-SIV open) | ciphertext + tag + reconstructed AAD | AEAD tag verification — the **final integrity anchor**; any prior mis-correction/tamper fails here (SR-R6), never silently-wrong plaintext | `CryptoError::Cipher` |
| 13 | `decrypt_with_key` — UTF-8 validation | recovered plaintext bytes | `core::str::from_utf8` on the borrowed buffer (transient bytes zeroized on drop) | `CryptoError::Encoding` |

**AAD ordering invariant (SR-R6, safety-critical):** the AAD passed to gate 12
is rebuilt from the **error-corrected** header recovered at gate 10, never a raw
prefix — order is `FEC-correct → structural-validate → AEAD-open(aad)`.

## Empirical demonstration — cargo-fuzz (Task 21)

Three `libFuzzer` targets under `fuzz/fuzz_targets/`:

| Target | Drives | Contract |
|--------|--------|----------|
| `decrypt` | `CryptoVault::decrypt_with_key(&key, from_utf8_lossy(data))` | full decrypt path (gates 1–13) always returns; never panics |
| `unwrap` | `CryptoVault::unwrap_key(&kek, from_utf8_lossy(data))` | envelope path (gates 1–12) always returns; never panics |
| `fec_crates` | `reedsolomon::ReedSolomon::{decode,decode_framed}` + `viterbi::CcsdsViterbiDecoder::decode_block` **directly, unguarded** | the own FEC crates are panic-safe on arbitrary bytes (SR-F5) |

### Local smoke run (2026-07-03, Windows 11 MSVC, nightly)

Each target built and ran cleanly; **zero crashes**:

| Target | Executions (≈30 s) | exec/s | Crashes |
|--------|--------------------|--------|---------|
| `decrypt` | 905 204 | ≈29 200 | 0 |
| `unwrap` | 871 384 | ≈28 109 | 0 |
| `fec_crates` | 4 884 | ≈157 (RS decode is heavy) | 0 |

> **Windows note.** `cargo +nightly fuzz build` works out of the box, but running
> the binary needs the ASan runtime DLL on `PATH`:
> `…/VC/Tools/MSVC/<ver>/bin/Hostx64/x64/clang_rt.asan_dynamic-x86_64.dll`
> (else `STATUS_DLL_NOT_FOUND` / `0xc0000135`). Prepend that directory before
> `cargo fuzz run`.

### Release CI gate (not run here)

The smoke run proves the targets build and find no immediate crash; it is **not**
the release bar. The SR-R5 / P0-4 release gate — run on a Linux CI runner — is:

> **≥ 24 CPU-hours or ≥ 100 M executions per target, zero crashes**, corpus
> seeded from the KAT + adversarial vectors (`tests/adversarial.rs`,
> `tests/kat.rs`). A fuzz-found crash is a release blocker and becomes a
> permanent regression test (upstream fix / fork of the offending FEC crate).

Until that sweep runs in CI, no-panic coverage in the default `cargo nextest`
suite is provided by `tests/proptest.rs::pt_decrypt_never_panics` (2048 arbitrary
base64 × arbitrary-key cases) and the per-module `*_never_panics_on_junk` unit
tests in `src/blob.rs`.
