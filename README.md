# cryptovault

A **self-contained authenticated-encryption vault** in Rust, composed over three
injected strategy traits:

| Layer | Default | Role |
|-------|---------|------|
| **KDF** | Argon2id (OWASP 2025: m=64 MiB, t=3, p=4) | passphrase → 32-byte key |
| **Cipher** | AES-256-GCM-SIV (RFC 8452, nonce-misuse resistant) | confidentiality + 128-bit auth tag |
| **FEC** | Reed-Solomon RS(255,223) | survive bit-rot |

Blob layout: `[version][u32 LE len][RS( nonce(12) ‖ ciphertext ‖ tag(16) )]`,
base64. Per-record `OsRng` nonce; the salt lives once per database, not per
record. Includes **envelope key-wrapping** (`wrap_key`/`unwrap_key`) for a
DEK/KEK model: a random Data Encryption Key wrapped under a passphrase-derived
KEK, so the passphrase can change in O(1) without re-encrypting data.

> **Status: work in progress.** Extracted from `magi-rs` and being hardened into
> a reusable, audited crate. See [`HANDOFF.md`](HANDOFF.md).

## Security model (summary)
- Confidentiality + integrity via AES-256-GCM-SIV (forgery ≤ 2^-128/record).
- Memory-hard KDF (Argon2id) against brute force; keys held in `Zeroizing`.
- Allocation-DoS guards on decrypt (version → length cap → body consistency).
- Vetted RustCrypto primitives for the cipher/KDF — **no rolled crypto**.

## Example

```rust
use cryptovault::CryptoVault;

let vault = CryptoVault::default();
let key = vault.derive_key("master-passphrase", &[0u8; 16]).unwrap();
let blob = vault.encrypt_with_key(&key, "sk-secret").unwrap();
assert_eq!(vault.decrypt_with_key(&key, &blob).unwrap(), "sk-secret");
```

## License

Licensed under either of **MIT** or **Apache-2.0** at your option.
