# Security & Quality Audit — `cryptovault` 0.1.0

- **Crate:** `cryptovault`
- **Audited revision:** `99db5d8` (tag `v0.1.0`)
- **Audit date:** 2026-07-03
- **Method:** five independent read-only passes (two cryptographic, adversarial-input/memory,
  DoS/CPU with measurements, FEC-correctness/spec-conformance, API/docs/deps/packaging),
  plus mechanical gates (`forbid(unsafe)` scan, dependency-tree review, `cargo audit`).
  FEC-dependency sources (`reedsolomon` 0.1.0, `viterbi` 0.0.1) were read to verify the
  no-panic boundary; RS parity and the CCSDS Viterbi impulse were re-derived from scratch to
  confirm the KAT anchors are genuinely independent.
- **Remediation branch:** `fix/audit-remediation` → target release **0.2.0**.

## Verdict

**SOUND for the published 0.1.0 — zero CRITICAL, zero security/correctness break.** The
cryptographic core (AEAD-first ordering, error-corrected-header-as-AAD, HKDF domain
separation, Argon2id, constant-time tag handling, OsRng-only randomness), the no-panic
contract, the FEC layer (RS/interleaver/Viterbi with syndrome-verified no-silent-miscorrection),
and the AEAD backstop are all confirmed correct and anchored by official + independent KATs.
The published crate does **not** warrant a yank.

Remediation targets one HIGH quality defect, five MEDIUM hardening/process items, and a set of
LOW/INFO refinements — collected here and fixed on `fix/audit-remediation` for a **0.2.0**
release (some fixes narrow the public API, which is a breaking change and therefore a minor
version bump under 0.x semver).

## Severity summary

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 5 |
| LOW | 12 |
| INFO | ~8 |

## Findings & remediation

Status legend: **OPEN** · **FIXED** · **DOC** (documented/accepted) · **DEFERRED** (needs a human/independent action).

### HIGH

| ID | Title | Location | Problem | Fix | Status |
|----|-------|----------|---------|-----|--------|
| **H1** | README usage examples do not compile | `README.md` (usage), `src/lib.rs` | `use cryptovault::CryptoVault;` fails `E0432` — the crate has **no root re-exports**; real path is `cryptovault::vault::CryptoVault`. The first example a user copies fails. No CI gate caught it (doctests not run; README not doc-included). | Add crate-root re-exports (`pub use vault::{CryptoVault, NoFec, generate_salt, generate_dek, constant_time_eq}; pub use error::{CryptoError, Result}; pub use fec::{ConcatenatedFec, ErrorCorrection};`); fix README paths; add the two README usage snippets as compiled `//!` crate-doc examples (mirrored, `cargo test --doc` verified) so they cannot drift. | **FIXED** (0.2.0) |

### MEDIUM

| ID | Title | Location | Problem | Fix | Status |
|----|-------|----------|---------|-----|--------|
| **M1** | Byte cores accept a master of any length (empty key silently encrypts) | `src/vault.rs` `encrypt_bytes_aad`/`decrypt_bytes_aad` | `derive_key` validates its inputs, but the byte cores (→ all five public doors) never check `master.len()`. HKDF accepts any-length IKM, so the cipher's `KEY_LEN` check is bypassed as a misuse detector — an empty/truncated key produces valid blobs under a key derivable from nothing. | Reject `master.len() != KEY_LEN` → `InvalidInput` at the top of the byte cores (one check covers all doors). Behavior-preserving for correct callers. | FIXED |
| **M2** | Argon2 64 MiB working memory freed unwiped | `src/kdf.rs` `derive_master` | The `argon2` crate frees its block buffer without wiping (verified in source); final-column blocks are key-equivalent → master-reconstructable material persists in freed heap. Contradicts the spec's own "no heap residue" claim. | Use `hash_password_into_with_memory` with a self-owned, drop-wiped block buffer; enable `argon2 = { features = ["zeroize"] }`. | FIXED |
| **M3** | Pre-authentication CPU-DoS: full FEC decode (~100 s for a max blob) runs before the AEAD | `src/vault.rs` `decrypt_bytes_aad`, `src/lib.rs` docs | A single ~24 MB structurally-valid junk blob (no valid key/tag) forces ~100 s single-thread CPU before authentication (~4000:1 amplification). Measured: 128 KiB→1.1 s, 1 MiB→9 s, 4 MiB→42 s, 10 MiB→~105 s. Memory (~80 MB) and `derive_key` DoS are documented; the decrypt CPU cost is not. | Document the decrypt-path CPU cost as an untrusted-caller DoS surface (rate-limit; cap accepted blob size below 10 MiB). Add a **configurable per-vault `max_blob_len` cap** (default `MAX_BLOB_LEN`) so a service can bound worst-case decode latency without a format change. | **FIXED** (0.2.0) — cap in Batch A; CPU-cost DoS docs added to the crate `//!`, `decrypt_with_key`, and `unwrap_key`. |
| **M4** | Doctests never run in CI | `.github/workflows/ci.yml`, `release.yml` | `cargo nextest run` does not run doctests and no `cargo test --doc` step exists — the ~8 doc examples are only human-checked (this is why H1 shipped). | Add a `cargo test --doc` step to the test job in both workflows. | **FIXED** (0.2.0) — added to `ci.yml` `test` job and `release.yml` `ci` job. |
| **M5** | `owasp_params()` leaks `argon2::Params` across the public boundary | `src/kdf.rs` | Returns a third-party type while `argon2` is not re-exported: an `argon2` 0.5→0.6 bump silently changes the public API (semver hazard) and callers can't name the type. | Make `owasp_params` `pub(crate)` (nothing outside the crate needs it); its `tests/kat.rs` pinning check moved to a `src/kdf.rs` unit test. | **FIXED** (0.2.0) |
| **M6** | SR-F5 "independent external review" is met by an OWNER self-sign-off | `docs/reviews/fec-0.1.0.signed.md` | The spec mandates *independent* eyes to break the single-author blind-spot; an owner sign-off is the same-author review the requirement exists to eliminate. Honestly disclosed + recorded as a follow-up under the gate's waiver path. | Obtain a genuinely independent review of `reedsolomon`/`viterbi` before claiming SR-F5, **or** amend the spec to accept an owner sign-off for 0.x. Cannot be discharged autonomously. | DEFERRED |

### LOW

| ID | Title | Location | Fix | Status |
|----|-------|----------|-----|--------|
| **L1** | Viterbi decoder-constructor `expect` → OOM panic on the decrypt path (`AllocationFailed`) | `src/fec/viterbi.rs` | Map `CcsdsViterbiDecoder::new` errors to `CryptoError::ErrorCorrection`; fix the `expect` rationale. | FIXED |
| **L2** | Fixed ~11 MB decoder scratch per call → ~16,000× memory amplification for tiny blobs | `src/fec/viterbi.rs` | Size `max_info_bits` to `8·min(VITERBI_CHUNK, actual max body)` (or reuse one decoder). | FIXED |
| **L3** | `HANDOFF.md` (internal `magi-rs` brief) ships in the published crate | `Cargo.toml` `exclude` | Add `HANDOFF.md` (and `tests/ber_provisional.rs`) to `exclude`. | **FIXED** (0.2.0) |
| **L4** | `pub mod blob` exposes forgeable wire plumbing (`encode_blob`/`decode_blob`/`validate_pre_fec`) | `src/lib.rs`, `src/blob.rs` | Make `blob` `pub(crate)` (minimize attack surface); blob-crafted integration tests migrated to `src/blob.rs` unit tests, remainder rewritten against the public API (all SC-1..8 still covered). Breaking → 0.2.0. | **FIXED** (0.2.0) |
| **L5** | No MSRV CI job (1.70 declared, unverified) | `.github/workflows/ci.yml` | Add an MSRV job (`dtolnay/rust-toolchain@1.70` + `cargo check`). | **FIXED** (0.2.0) — `msrv` job (`@1.70` + `cargo check --all-targets`) added to `ci.yml`. |
| **L6** | Passphrase accepted as plain `&str` (no `secrecy::SecretString`) | `src/vault.rs` `derive_key` | SHOULD item; host-memory compromise is out of the threat model. Documented as an accepted limitation for 0.x (adding `secrecy` is unjustified surface per minimize-attack-surface). | DOC |
| **L7** | `CsprngLayer::new` takes the seed by value (un-zeroized array copy) | `src/fec/interleaver.rs` | Accept `&[u8]`/`&Zeroizing<..>` and copy internally into the `Zeroizing` field. | FIXED |
| **L8** | `zeroize` features not enabled on `aes-gcm-siv`/`chacha20`/`argon2` | `Cargo.toml` | Enable the optional `zeroize` feature where available (wipes cipher/HKDF/Argon2 transient state). | **FIXED** (0.2.0) — `chacha20` enabled; `argon2` already enabled (M2, Batch A); `aes-gcm-siv` 0.11 exposes **no** `zeroize` feature (verified via `cargo add --dry-run`; the AES key schedule already zeroizes on drop), so nothing to enable there. |
| **L9** | No purpose/domain separation between data and envelope blobs (empty-salt aliasing) | `src/vault.rs` AAD build | Bind a fixed **purpose label** (`data` vs `wrap`) into the AAD so the two front doors are not cross-decryptable. Format-adjacent (AAD) change → 0.2.0. | FIXED |
| **L10** | `wrap_key`/`unwrap_key`/`rewrap` do not validate `salt.len()` | `src/vault.rs` | Any-length salt binds correctly as AAD; documented. Left flexible by design (envelope salt need not equal `SALT_LEN`). | DOC |
| **L11** | KAT reference corpus is thin (single RS + single Viterbi vector) | `tests/kat_reference.rs` | Add additional independent multi-symbol RS error patterns + a small trellis-state Viterbi KAT suite. | **FIXED** (0.2.0) — 2 more independent RS(255,223) error patterns (12- and 16-symbol recovery + 17-symbol fail-loud) and a distinct-stream Viterbi trellis round-trip, in `tests/kat_reference.rs` and `tests/kat.rs`. |
| **L12** | Optional CSPRNG interleaver has no ergonomic vault-wiring path | `src/fec/mod.rs`, `src/vault.rs` | Add a documented constructor that wires the HKDF interleaver seed into a `BlockThenCsprng` `ConcatenatedFec` from a master. | **FIXED** (0.2.0) — `ConcatenatedFec::with_csprng_from_master(master, depth)` HKDF-derives the seed and builds `BlockThenCsprng`; documented opt-in/non-security, unit-tested via `CryptoVault::new`. |
| **L13** | Crate docs reference the gitignored `sbtdd/spec-behavior.md` (dangling on docs.rs) | `src/lib.rs` | Point to the shipped `docs/*` instead, or drop the line. | **FIXED** (0.2.0) — crate `//!` now points to the shipped `docs/` directory. |

### INFO

| ID | Title | Fix | Status |
|----|-------|-----|--------|
| **N1** | File headers say `// Version: 2.0.0` while the crate is 0.1.0 | Set headers to the crate version. | **FIXED** (0.2.0) — all `src/**/*.rs` headers set to `0.2.0`, matching the crate version. |
| **N2** | Two decrypt-path messages interpolate the attacker's own input length (b64 len, base64 crate error, unreachable guard) | Harmonize to fixed generic strings for full SR-R7 message consistency (b64-length echo + unreachable `body.len()` guard fixed; base64-crate `Encoding` error left as-is). | FIXED |
| **N3** | README states point-in-time "113 tests / ~97% coverage" | Replace exact numbers with badges. | **FIXED** (0.2.0) — replaced with a qualitative statement + CI-badge reference (no drift-prone numbers). |
| **N4** | Public direct FEC codecs (`ReedSolomonCodec`/`ViterbiCodec`/`BlockInterleaver`) do not self-enforce `MAX_BLOB_LEN` | Rustdoc note that direct callers must impose their own cap. | **FIXED** (0.2.0) — no-`MAX_BLOB_LEN`-cap notes added to `ReedSolomonCodec::decode`, `ViterbiCodec::decode`, and the interleaver `deinterleave` methods. |
| **N5** | The ≥24 CPU-h / ≥100 M-exec fuzz release bar has not run (0.1.0 shipped on a smoke run) | Track as a CI/release condition; run before any SR-R5 conformance claim. | DEFERRED |
| **N6** | Spec §7 writes `HKDF-Expand(master, info)` but the impl runs full Extract-then-Expand (`salt=None`) | Docs-only: align the spec text to the (RFC-5869-correct) implementation. | **SKIP** — `sbtdd/spec-behavior.md` is gitignored and not part of the published crate; no docs.rs/crate-facing impact. Noted for the record: the impl runs full HKDF Extract-then-Expand with `salt=None` (RFC-5869-correct), already documented in the shipped `tests/kat.rs` provenance note. No action on a non-shipped file. |

## Confirmed correct (positive assurance)

- **AEAD:** AES-256-GCM-SIV per RFC 8452; fresh 12-byte `OsRng` nonce per record (rewrap included), fail-closed on RNG failure; AAD on decrypt is the **error-corrected** recovered header (SR-R6 ordering exact); tag compared constant-time inside the vetted crate, which re-encrypts on failure (never releases unauthenticated plaintext). RFC 8452 App. C.2 KATs pass through production code.
- **KDF/HKDF:** Argon2id V0x13 at pinned OWASP params (64 MiB/t3/p4), input-validated; HKDF-SHA256 domain separation with distinct `info`, seed never equals the AEAD key; RFC 9106 + RFC 5869 KATs.
- **No-panic:** every `unwrap`/`expect`/slice/arithmetic on the decrypt/unwrap path is guarded or statically unreachable; the FEC-dependency boundary is panic-safe on every input the structural validation admits (Forney div-by-zero guarded, `try_reserve`, `saturating_add`). `#![forbid(unsafe_code)]` crate-wide + both FEC deps.
- **DoS (memory/alloc):** `MAX_B64_LEN`/`MAX_BLOB_LEN` gates ordered before allocation; header `plaintext_len` never drives allocation.
- **FEC:** RS(255,223) syndrome-verified no-silent-miscorrection (at dep source); deterministic block interleaver invertible with a mathematically-sound P0-2 burst bound; Viterbi `2L+2`, chunked at 124 950 B, `MAX_BLOB_LEN` arithmetic exact and RX-derivable without bootstrap; blob format + header-inside-FEC + AAD; **KAT anchors re-derived from scratch (genuinely independent)**.
- **Packaging:** minimal symmetric DI API, `Send+Sync`, `Zeroizing` at every secret boundary; excellent Rustdoc (`# Errors` + all security caveats user-facing); lean fully-justified dependency tree; exact FEC pins; non-waivable release-gate; honest owner sign-off.

## Remediation plan (0.2.0)

1. Crypto/security code (TDD): M1, M2, M3-cap, L1, L2, L7, N2.
2. API/packaging: H1 re-exports, M5 + L4 `pub(crate)`, L3 `exclude`, L8 `zeroize` features, L9 AAD purpose label, N1 headers, version → 0.2.0.
3. CI/docs: M4 doctest job, L5 MSRV job, M3 CPU-DoS docs, L11 KAT corpus, L12 CSPRNG helper, L13/N3/N4/N6 docs, README fix + doctest.
4. Tracked (human/independent): M6 independent FEC review, N5 fuzz sweep, L6 SecretString (accepted), L10 (accepted).

Each code fix follows strict TDD (`test:` reproduce → `fix:`) with the full §0.1 gate green before commit.

## Remediation summary (0.2.0)

The 0.2.0 remediation shipped across three batches (A: crypto/security code; B:
API/packaging; C: CI/docs). Final status of every finding:

**Shipped — FIXED**

| Batch | Findings |
|-------|----------|
| A (crypto/security, TDD) | M1, M2, M3-cap, L1, L2, L7, N2 |
| B (API/packaging) | H1, M5, L4, L3, L8, L9, N1, version → 0.2.0 |
| C (CI/docs) | **M4** (doctest step in both workflows), **L5** (MSRV 1.70 job), **M3-docs** (decrypt-path CPU-DoS docs), **L11** (extended RS/Viterbi KAT corpus), **L12** (`with_csprng_from_master` helper), **L13** (docs.rs link repoint), **N3** (README numbers → qualitative + badge), **N4** (direct-codec no-cap notes) |

With M3-cap (A) + M3-docs (C), **M3 is now fully FIXED**.

**DOC (documented / accepted, no code change)**

- **L6** — passphrase as `&str` (no `secrecy::SecretString`): host-memory compromise is out of the threat model; adding `secrecy` is unjustified surface (minimize-attack-surface). Accepted for 0.x.
- **L10** — `wrap_key`/`unwrap_key`/`rewrap` do not validate `salt.len()`: any-length salt binds correctly as AAD; envelope salt need not equal `SALT_LEN`. Left flexible by design.

**SKIP (non-shipped artifact)**

- **N6** — the spec-text `HKDF-Expand` wording lives in the gitignored, non-published `sbtdd/spec-behavior.md`; no crate/docs.rs impact. The implementation runs RFC-5869-correct full Extract-then-Expand (`salt=None`), already documented in the shipped `tests/kat.rs`. No action on a non-shipped file.

**DEFERRED (needs a human / independent action — not dischargeable autonomously)**

- **M6** — genuinely independent (non-owner) external review of the `reedsolomon`/`viterbi` FEC crates, required before claiming SR-F5. Recorded under the gate's waiver path.
- **N5** — the ≥24 CPU-h / ≥100 M-exec `cargo-fuzz` release sweep (0.1.0 shipped on a smoke run); tracked as a CI/release condition before any SR-R5 conformance claim.

All §0.1 gates (fmt, clippy `-D warnings`, nextest, `cargo test --doc`, release build, `cargo doc --no-deps`, `cargo audit`) are green on the remediated tree.
