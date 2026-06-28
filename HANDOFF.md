# HANDOFF — `cryptovault` crate

> Agent brief for hardening this crate into a robust, reusable, audited library.
> Self-contained: you do not need the `magi` repo.

## Goal
`src/lib.rs` is the working module extracted verbatim from `magi-rs`
(`src/utils/crypto.rs`): trait-composed `CryptoVault` (Argon2id + AES-256-GCM-SIV
+ Reed-Solomon), the byte cores (`encrypt_bytes`/`decrypt_bytes`), and the
envelope helpers (`wrap_key`/`unwrap_key`). It compiles and its tests pass.
**Harden it to a "by-the-book" reusable crate** without weakening any existing
guarantee. Keep the trait-based composition and the audited defaults.

## MUST (core robustness)
1. **AAD support.** Add an `aad: &[u8]` path to `AuthenticatedCipher`
   (`aes-gcm-siv` supports `Payload { msg, aad }`) and to `wrap_key`/`unwrap_key`.
   Then **bind the blob header (version + length) as AAD** so the whole blob is
   authenticated, not just the body. (In the vault, the per-DB salt is passed as
   AAD when wrapping the DEK — the explicit salt↔DEK binding.)
2. **`#![forbid(unsafe_code)]`** at the crate root.
3. **No-panic on adversarial input.** Audit every `unwrap`/`expect`/index in the
   decrypt path; add a `cargo-fuzz` target on `decrypt_bytes`/`unwrap_key`.
4. **Zeroize secret intermediates** + offer a `Zeroizing`-returning plaintext
   decrypt (the current `decrypt_with_key` returns a plain `String`).
5. **CSPRNG generation helpers:** `generate_salt()`, `generate_dek()` (OsRng,
   `Zeroizing`) so consumers don't hand-roll key/salt generation.
6. **Envelope rotation API:** `rewrap(old_kek, new_kek, blob)` (unwrap+rewrap) for
   passphrase change.

## SHOULD (reuse rigor)
- **Type-safe newtypes:** `Key`, `Salt`, `Nonce`, `SecretBytes` (length enforced
  at construction) instead of bare `&[u8]` — misuse-resistance.
- **`secrecy::SecretString`** for the passphrase (no `Debug`/`Display` leak).
- **`subtle`** constant-time comparison wherever secrets/tags are compared.
- **Version-dispatch:** make the leading version byte actually select
  `(kdf, cipher, fec)` so algorithms can rotate without bricking old blobs.
- **KATs** (RFC 8452 AES-GCM-SIV, Argon2 vectors) + `proptest` round-trip and
  "decrypt never panics".
- **Generalize the docs:** remove `magi-rs`-specific references (`vault_meta`,
  `EncryptedSqliteMemory`, keyring `magi-rs-internal`); document a generic threat
  model + what it does NOT defend against (host compromise reading memory, side
  channels, etc.).
- **RNG injection** (default `OsRng`) for deterministic nonce tests.

## NICE (YAGNI-gated)
- Alternative cipher (ChaCha20-Poly1305) behind the trait for non-AES-NI hosts.
- HKDF sub-key derivation with domain separation if multiple keys are derived.
- Feature-gate the FEC layer.

## AVOID — minimize attack surface (security principle)
- **Do NOT add cryptographic surface you don't need.** Every extra primitive,
  mode, option, or config knob is more code to audit and more that can go wrong —
  added crypto surface can *reduce* security. The NICE items are opt-in only when
  a concrete, justified need arises; default to the smallest correct API.
- **Do NOT roll your own cipher / KDF / MAC** — use the vetted RustCrypto crates.
  (Rolling the *FEC* is acceptable because it is **not** a security primitive —
  see the sibling `reedsolomon` crate; the same does **not** apply to AEAD/KDF.)

## Dependency note
The FEC currently uses the third-party `reed-solomon` v0.2 (simple, lightly
maintained). **Switch to the [`reedsolomon`](https://crates.io/crates/reedsolomon)
crate** (sibling project: native GF(2^8) RS(255,223), no third-party FEC) once it
ships `0.1.0`. Keep cipher/KDF on the vetted RustCrypto crates — do **not** roll
those.

## Quality gates (every commit)
- `cargo nextest run` green · `cargo clippy --all-targets -- -D warnings` clean ·
  `cargo fmt --check` · `cargo build --release` · `cargo doc --no-deps` (no
  warnings) · `cargo audit` clean.
- Rustdoc on all public items; no magic numbers; file header
  (`// Author / Version / Date`). Remove the `#[allow(dead_code)]` on the
  envelope helpers (in a lib they are public API, not dead).
- TDD Red→Green→Refactor; atomic commits; English imperative messages; no AI
  mentions; no `Co-Authored-By`. Every change behavior-preserving unless a MUST
  item changes the contract (then version + document it).

## Relationship to the vault feature
This crate is the foundation of the `magi-rs` **Vault** feature (encrypted
secrets store, envelope DEK/KEK, passphrase change). The AAD + rewrap + gen
helpers above are exactly what that feature consumes.
