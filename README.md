# cryptovault

A **self-contained authenticated-encryption vault** in Rust, composed over three
injected strategy traits:

| Layer | Default | Role |
|-------|---------|------|
| **KDF** | Argon2id (OWASP 2025: m=64 MiB, t=3, p=4) → HKDF-SHA256 sub-keys | passphrase → 32-byte master |
| **Cipher** | AES-256-GCM-SIV (RFC 8452, nonce-misuse resistant) | confidentiality + 128-bit auth tag |
| **FEC** | concatenated: Reed-Solomon `RS(255,223)` → block interleaver → Viterbi `K=7 R=1/2` | survive channel corruption / bit-rot |

Blob layout: `Viterbi( interleave( RS( version(1) ‖ len(u32 LE) ‖ nonce(12) ‖
ciphertext ‖ tag(16) ) ) )`, base64. The header lives **inside** the FEC envelope
(channel-corrected) *and* is bound as AAD (tamper-evident). Per-record `OsRng`
nonce; the salt lives once per context, not per record. Includes **envelope
key-wrapping** (`wrap_key`/`unwrap_key`) for a DEK/KEK model: a random Data
Encryption Key wrapped under a passphrase-derived KEK, so the passphrase can
change in O(1) without re-encrypting data.

> **Status: work in progress**, being hardened into a reusable, audited crate.
> See [`HANDOFF.md`](HANDOFF.md).

## Operational constraints

Read these before deploying — they are caller contracts the crate cannot enforce
(full detail in the crate-level Rustdoc):

- **All-or-nothing recovery.** A blob fully recovers or fully fails — no partial
  recovery (the AEAD needs the complete ciphertext). Keep each plaintext ≤
  `RECOMMENDED_MAX_PAYLOAD` (**128 KiB**, BER-derived) and **frame large data into
  multiple small blobs** so one bad frame does not doom the rest.
- **Concurrency.** A decrypt peaks at **≈ 80 MB per blob**; there is no built-in
  limit, so **bound concurrent decrypts** (semaphore / worker pool).
- **Nonce birthday bound ≈ 2⁴⁸ records/key** — rekey long-lived keys.
- **Salt uniqueness is the caller's contract** — obtain every salt from
  `generate_salt()`; reuse across contexts collides the master key.
- **FEC is not security.** Confidentiality and integrity come *only* from the
  AEAD. The optional CSPRNG interleaver layer is obfuscation with a documented
  active-adversary availability limitation (DC-1); the default interleaver is
  keyless.

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
