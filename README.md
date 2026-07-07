# cryptovault

**Authenticated encryption resilient over interference channels** — AES-256-GCM-SIV
over Argon2id/HKDF, followed by a concatenated Reed-Solomon + interleaver + Viterbi
forward-error-correction (FEC) layer.

[![CI](https://github.com/BolivarTech/cryptovault/actions/workflows/ci.yml/badge.svg)](https://github.com/BolivarTech/cryptovault/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/cryptovault.svg)](https://crates.io/crates/cryptovault)
[![docs.rs](https://img.shields.io/docsrs/cryptovault)](https://docs.rs/cryptovault)
[![license](https://img.shields.io/crates/l/cryptovault.svg)](#license)

---

## What it does

`cryptovault` composes **two orthogonal capabilities** into one pipeline, and keeps
them strictly separate:

1. **Cryptographic security** (confidentiality + integrity) — an AEAD over a
   memory-hard KDF. This is the **only** source of security.
2. **Channel resilience** (error/burst correction) — a concatenated FEC. This is
   **not** security; it is robustness against a noisy or lossy transport.

The security layer is applied **first**, the resilience layer **after**, so the FEC
can never weaken a cryptographic guarantee:

```text
TX:  data → [AEAD: Argon2id → HKDF-SHA256 + AES-256-GCM-SIV, header bound as AAD]
          → [Reed-Solomon RS(255,223)]
          → [interleaver: deterministic block (default) + optional CSPRNG layer]
          → [Viterbi K=7 R=1/2, hard-decision]  → CHANNEL
RX:  CHANNEL → Viterbi → de-interleave → RS decode → AEAD open → data
```

Concatenated code: `VT(interleave(RS(AEAD(data))))`.

### Blob layout

The output is a base64 string over:

```text
Viterbi( interleave( RS( version(1B) ‖ plaintext_len(u32 LE) ‖ nonce(12B) ‖ ciphertext ‖ tag(16B) ) ) )
```

**Every byte, header included, is FEC-protected.** The header (`version` +
`plaintext_len`) lives *inside* the FEC envelope, so channel corruption of it is
error-corrected rather than fatal, **and** it is bound as AEAD associated data (AAD),
so tampering beyond FEC capacity fails the authentication tag. The header is both
*recoverable* and *tamper-evident*.

The crate also provides **envelope key-wrapping** (`wrap_key` / `unwrap_key`) for a
Data-Encryption-Key / Key-Encryption-Key (DEK/KEK) model, plus `rewrap` for KEK
rotation — the passphrase can change in O(1) without re-encrypting the data.

## Security model

| Property | Mechanism | Level |
|---|---|---|
| Confidentiality | AES-256-GCM-SIV (RFC 8452) | 256-bit key, IND-CCA2 |
| Integrity / authenticity | 128-bit GCM-SIV tag + AAD-bound header | forgery ≤ 2⁻¹²⁸ per record |
| Nonce-misuse resistance | SIV construction | a nonce collision leaks only plaintext equality |
| Brute-force resistance | Argon2id, OWASP-2025 (m=64 MiB, t=3, p=4) | memory-hard |
| Domain separation | HKDF-SHA256 | AEAD key ⟂ interleaver seed |
| Memory safety | `#![forbid(unsafe_code)]`, pure Rust | UB impossible by construction |
| Secret hygiene | `Zeroizing`, `subtle` | no heap residue, constant-time tag/secret compare |

**Target: 256-bit confidentiality / 128-bit authentication.** The 256-bit AES key
also gives ~128-bit post-quantum margin (Grover). The 128-bit tag is fixed by
RFC 8452 and is the standard, ample authentication level.

### The FEC is resilience, NOT security

Confidentiality and integrity come **only** from the AEAD, applied first. The
default interleaver is a public, keyless **deterministic block interleaver** (provable
burst-spreading — no obfuscation, needs none). The optional CSPRNG interleaver layer
adds defense-in-depth obfuscation that holds *only because a real AEAD sits
underneath* — it adds no confidentiality or integrity of its own
(`fixed < LFSR < CSPRNG < real AEAD`).

### Out of scope (what it does NOT defend against)

- Host memory compromise (the unwrapped key lives in RAM during a session).
- Side channels of the underlying primitives beyond constant-time secret compares.
- Traffic analysis / metadata (blob size approximates plaintext length).
- Passphrase / keyring theft or coercion.
- **Confidentiality via the FEC / interleaver** — it is obfuscation only.
- **Active-adversary FEC defeat (DC-1).** An adversary who both drives encryption
  (an oracle) *and* injects channel errors could learn the static per-key CSPRNG
  permutation and craft bursts that degrade **FEC resilience (availability) only** —
  never AEAD confidentiality or integrity. Per-record interleaver variation is
  future work.
- **Replay** — a protocol concern (the caller's nonce/sequence tracking).

### Operational contracts (the caller must honor)

These are constraints the crate cannot enforce for you; read them before deploying
(full detail in the crate-level Rustdoc):

- **All-or-nothing recovery (availability cliff).** A blob either fully recovers or
  fully fails — there is no partial recovery, because the AEAD needs the *complete*
  ciphertext. Keep each plaintext at or below **`RECOMMENDED_MAX_PAYLOAD` (128 KiB,
  BER-derived)** and **frame large data into multiple small blobs**, so one bad frame
  does not doom the rest. The hard cap is `MAX_PLAINTEXT_LEN` (10 MiB).
- **Concurrency.** A single decrypt peaks at **≈ 80 MB per blob**; there is no
  built-in limit, so **bound concurrent decrypts** with a semaphore or worker pool.
- **Nonce birthday bound ≈ 2⁴⁸ records/key** — rekey long-lived keys before then.
- **Salt uniqueness is the caller's contract** — obtain every salt from
  `generate_salt()` (OsRng); reuse across contexts collides the master key.
- **`derive_key` runs Argon2 (memory-hard, expensive).** Call it **once per session**
  and cache the returned key; the per-record and unwrap/decrypt paths never invoke
  Argon2, so an attacker submitting many blobs triggers only cheap FEC-decode + one
  AEAD-open per blob — not per-record memory-hard work.

### Framing is the caller's responsibility

The crate produces and consumes a **single, length-delimited blob** and performs no
node synchronization. Delivering blob boundaries (framing / packetization) is the
caller's job; FEC correction capacity applies only *within* one correctly-framed blob.

## Usage

> These examples are mirrored as compiled doctests in the crate-level Rustdoc
> (`cargo test --doc`), so they are verified against the public API and cannot drift.

```rust
use cryptovault::CryptoVault;

let vault = CryptoVault::default();

// Derive a session key once (Argon2id is memory-hard — cache the result).
let salt = [0u8; 16]; // in production: cryptovault::generate_salt()?
let key = vault.derive_key("master-passphrase", &salt).unwrap();

// Encrypt-and-authenticate, survive channel corruption, then recover.
let blob = vault.encrypt_with_key(&key, "sk-secret").unwrap();
let recovered = vault.decrypt_with_key(&key, &blob).unwrap();
assert_eq!(recovered.as_str(), "sk-secret");
```

### Envelope key-wrapping (DEK/KEK)

```rust
use cryptovault::{CryptoVault, generate_dek, generate_salt};

let vault = CryptoVault::default();

let salt = generate_salt().unwrap();                       // per-context, once
let kek = vault.derive_key("master-passphrase", &salt).unwrap();
let dek = generate_dek().unwrap();                          // random 32-byte DEK

// The salt is bound as AAD, tying the wrapped DEK to its context.
let wrapped = vault.wrap_key(&kek, &salt, &dek).unwrap();
let unwrapped = vault.unwrap_key(&kek, &salt, &wrapped).unwrap();
assert_eq!(&*unwrapped, &*dek);
```

### AEAD-only (no FEC) or a custom FEC strategy

The error-correction layer is an **injectable strategy** (`ErrorCorrection`).
`CryptoVault::default()` wires the concatenated FEC; `CryptoVault::new(...)` accepts
any strategy. If you only need the **authenticated encryption** — your transport is
already reliable, or you want to bypass the FEC to isolate a codec issue — inject
`NoFec`, an identity codec. Confidentiality and integrity are **fully preserved** (they
come only from the AEAD, applied first); *only* channel resilience is dropped.

> A `NoFec` blob is **not** interchangeable with a default (FEC-protected) blob — the
> wire format differs, so decode with the same strategy you encoded with.

```rust
use cryptovault::{CryptoVault, NoFec};
use cryptovault::kdf::Argon2Kdf;
use cryptovault::cipher::Aes256GcmSivCipher;

// AEAD-only: inject NoFec to disable the concatenated FEC stack.
let vault = CryptoVault::new(
    Box::new(Argon2Kdf),
    Box::new(Aes256GcmSivCipher),
    Box::new(NoFec),
);

let salt = [0u8; 16]; // in production: cryptovault::generate_salt()?
let key = vault.derive_key("master-passphrase", &salt).unwrap();
let blob = vault.encrypt_with_key(&key, "sk-secret").unwrap();
let recovered = vault.decrypt_with_key(&key, &blob).unwrap();
assert_eq!(recovered.as_str(), "sk-secret");
```

To supply **your own** forward-error-correction, implement the `ErrorCorrection` trait
(three methods — `encode` adds redundancy, `decode` corrects then truncates to
`pre_len`, and `validate_pre_fec` caps the received length to bound allocation) and
inject it the same way:

```rust
use cryptovault::{CryptoVault, ErrorCorrection, CryptoError, Result, MAX_BLOB_LEN};
use cryptovault::kdf::Argon2Kdf;
use cryptovault::cipher::Aes256GcmSivCipher;

struct MyFec; // replace the bodies with your own error-correcting codec

impl ErrorCorrection for MyFec {
    fn encode(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec() // add your redundancy here
    }
    fn decode(&self, encoded: &[u8], pre_len: usize) -> Result<Vec<u8>> {
        let end = pre_len.min(encoded.len()); // run correction, then truncate
        Ok(encoded[..end].to_vec())
    }
    fn validate_pre_fec(&self, received: &[u8]) -> Result<usize> {
        if received.len() > MAX_BLOB_LEN {
            return Err(CryptoError::InvalidInput("input exceeds maximum size".into()));
        }
        Ok(received.len())
    }
}

let vault =
    CryptoVault::new(Box::new(Argon2Kdf), Box::new(Aes256GcmSivCipher), Box::new(MyFec));
let key = vault.derive_key("master-passphrase", &[0u8; 16]).unwrap();
let blob = vault.encrypt_with_key(&key, "secret").unwrap();
assert_eq!(vault.decrypt_with_key(&key, &blob).unwrap().as_str(), "secret");
```

## Quality posture

`cryptovault` is engineered to an internal, by-the-book audited bar:

- **`#![forbid(unsafe_code)]`** at the crate root; both FEC crates are pure-Rust,
  no-unsafe → panic-only boundary risk, no undefined behavior.
- **No panic on adversarial input** — every FEC/decrypt entry point is enumerated and
  gated by structural validation *before* any allocation or codec runs
  (see [`docs/no-panic.md`](docs/no-panic.md)), backed by `cargo-fuzz` targets over
  the full decrypt path and the FEC crates directly.
- **Known-Answer Tests** against independent references — RFC 8452 (AES-GCM-SIV),
  RFC 9106 (Argon2id), RFC 5869 (HKDF), a third-party `reedsolo` RS(255,223) parity
  vector, and the CCSDS K=7 R=1/2 Viterbi impulse response.
- **Comprehensive test suite green** (unit + doctests + KATs); `clippy -D warnings`,
  `cargo fmt`, `cargo doc` (no warnings), and `cargo audit` gate every commit, with
  an MSRV check in CI. See the CI badge for the current status.
- Vetted **RustCrypto** primitives for the cipher/KDF/MAC/HKDF — **no rolled crypto**.
  Only the FEC (a non-security layer) is BolivarTech's own code.

## MSRV

Rust **1.96** or newer.

## License

Licensed under either of

- **MIT** license ([LICENSE-MIT](LICENSE-MIT)), or
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this crate by you, as defined in the Apache-2.0 license, shall be
dual-licensed as above, without any additional terms or conditions.

Copyright © 2026 Julian Bolivar / BolivarTech.
