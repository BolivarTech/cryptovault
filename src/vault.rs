// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Public facade: the `CryptoVault` composing the three strategy traits, plus
//! envelope key-wrapping and generation helpers (implemented in Tasks 15+,
//! SR-C5/C6/C8).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use zeroize::Zeroizing;

use crate::blob::{decode_blob, encode_blob};
use crate::cipher::{sample_nonce, Aes256GcmSivCipher, AuthenticatedCipher};
use crate::error::{CryptoError, Result};
use crate::fec::{ConcatenatedFec, ErrorCorrection};
use crate::kdf::{expand_aead_key, Argon2Kdf, KeyDerivation};
use crate::{BLOB_VERSION, HEADER_LEN, MAX_B64_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN, SALT_LEN};

/// Identity [`ErrorCorrection`] — the AEAD-only degraded-but-secure fallback.
///
/// Injecting `NoFec` into [`CryptoVault::new`] disables the concatenated FEC
/// stack entirely: `encode` returns its input unchanged and `decode` merely
/// truncates to the pre-encode length. Confidentiality and integrity are
/// **fully preserved** (they come only from the AEAD, applied first); only the
/// channel-resilience layer is dropped. Use it when the FEC stack must be
/// bypassed (e.g. a clean transport, or to isolate a FEC-crate issue).
///
/// A fieldless strategy struct — construct it directly (`NoFec`); it holds no
/// state.
///
/// # Examples
/// ```
/// use cryptovault::fec::ErrorCorrection;
/// use cryptovault::vault::NoFec;
/// assert_eq!(NoFec.encode(b"abc"), b"abc");
/// assert_eq!(NoFec.decode(b"abcdef", 3).unwrap(), b"abc");
/// ```
pub struct NoFec;

impl ErrorCorrection for NoFec {
    /// Returns `data` unchanged (identity encode).
    fn encode(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    /// Returns `encoded` truncated to `pre_len` (identity decode).
    ///
    /// `pre_len` is clamped to `encoded.len()`, so an out-of-range length never
    /// panics (SR-R5 no-panic contract).
    ///
    /// # Errors
    /// Infallible in practice; the [`Result`] keeps the [`ErrorCorrection`]
    /// contract uniform with the fallible concatenated stack.
    fn decode(&self, encoded: &[u8], pre_len: usize) -> Result<Vec<u8>> {
        let end = pre_len.min(encoded.len());
        Ok(encoded[..end].to_vec())
    }
}

/// The public authenticated-encryption facade composing the three injectable
/// strategy traits (SR-C2 / SR-C5 / SR-F4).
///
/// `CryptoVault` wires a [`KeyDerivation`] (Argon2id master), an
/// [`AuthenticatedCipher`] (AES-256-GCM-SIV), and an [`ErrorCorrection`] stack
/// (the concatenated FEC) into one pipeline: AEAD **first** (the only source of
/// security), FEC **after** (resilience, never security). Build it with
/// [`CryptoVault::default`] for the audited defaults, or [`CryptoVault::new`] to
/// inject custom strategies (tests, deterministic nonces, algorithm rotation).
///
/// The vault holds **no secret state**: the master returned by
/// [`derive_key`](Self::derive_key) is cached by the *caller* in [`Zeroizing`]
/// and passed per call, so the vault is immutable after construction and
/// `Send + Sync` — a single instance can encrypt/decrypt concurrently.
///
/// # ⚠️ Memory
///
/// Decryption is **memory-heavy**. Each `decrypt` call holds several
/// O(blob)-sized buffers at once (base64 input, decoded blob, Viterbi output,
/// de-interleaved stream, RS output, plaintext), so at the 10 MiB plaintext cap
/// ([`crate::MAX_PLAINTEXT_LEN`]) a single decrypt **peaks at ≈ 80 MB — roughly
/// 8× the payload**. There is **NO built-in concurrency limit**: `N` concurrent
/// decrypts consume **≈ `N` × 80 MB**, so **callers MUST bound the number of
/// concurrent decrypts** (a semaphore / worker pool) or risk out-of-memory.
/// Concurrency policy is deliberately a caller/service-layer concern
/// (minimize-surface); the vault stays single-blob-per-call.
///
/// # Examples
/// ```
/// use cryptovault::vault::CryptoVault;
/// let vault = CryptoVault::default();
/// let master = vault.derive_key("correct horse battery staple", &[0u8; 16]).unwrap();
/// assert_eq!(master.len(), 32);
/// ```
pub struct CryptoVault {
    /// Master-key derivation strategy (Argon2id by default).
    kdf: Box<dyn KeyDerivation>,
    /// Authenticated cipher strategy (AES-256-GCM-SIV by default).
    cipher: Box<dyn AuthenticatedCipher>,
    /// Error-correction strategy (the concatenated FEC by default).
    fec: Box<dyn ErrorCorrection>,
}

impl CryptoVault {
    /// Constructs a vault from injected strategies (dependency injection).
    ///
    /// Prefer [`CryptoVault::default`] for production (audited wiring); use `new`
    /// for tests, deterministic-nonce ciphers, an AEAD-only [`NoFec`] stack, or
    /// future algorithm rotation.
    ///
    /// # Parameters
    /// - `kdf`: the master-key derivation strategy.
    /// - `cipher`: the authenticated cipher strategy.
    /// - `fec`: the error-correction strategy.
    ///
    /// # Returns
    /// The composed vault.
    #[must_use]
    pub fn new(
        kdf: Box<dyn KeyDerivation>,
        cipher: Box<dyn AuthenticatedCipher>,
        fec: Box<dyn ErrorCorrection>,
    ) -> Self {
        Self { kdf, cipher, fec }
    }

    /// Derives the session **master** secret from a passphrase and per-context
    /// salt (SR-C2), once per session.
    ///
    /// The returned value is the *master* — the crate HKDF-expands it internally
    /// into the AEAD sub-key and interleaver seed (SR-C3); **callers never handle
    /// those sub-keys**. Cache this master in [`Zeroizing`] and pass it to the
    /// encrypt / decrypt / envelope operations; Argon2id runs only here, never
    /// per record.
    ///
    /// # Parameters
    /// - `password`: the passphrase (must be non-empty).
    /// - `salt`: the per-context salt (must be exactly [`crate::SALT_LEN`] bytes;
    ///   obtain it from `generate_salt()`).
    ///
    /// # Returns
    /// The [`Zeroizing`]-wrapped 32-byte master secret (wiped on drop).
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if `password` is empty or `salt` is not
    /// [`crate::SALT_LEN`] bytes; [`CryptoError::KeyDerivation`] if Argon2id
    /// fails internally.
    pub fn derive_key(&self, password: &str, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if password.is_empty() {
            return Err(CryptoError::InvalidInput(
                "password must not be empty".into(),
            ));
        }
        if salt.len() != SALT_LEN {
            return Err(CryptoError::InvalidInput(format!(
                "salt must be exactly {SALT_LEN} bytes, got {}",
                salt.len()
            )));
        }
        self.kdf.derive_master(password.as_bytes(), salt)
    }

    /// Encrypts and authenticates `pt` into a base64 blob — the shared byte core
    /// behind the public UTF-8 and envelope front doors (SR-C1/C3/C4, SR-R4).
    ///
    /// Pipeline: bound the plaintext size (SR-R4) → HKDF-expand the AEAD sub-key
    /// (SR-C3) → sample a fresh nonce (SR-C1) → AES-256-GCM-SIV encrypt with the
    /// `version ‖ plaintext_len` header bound as **AAD** (SR-C4) → wrap
    /// `nonce ‖ ciphertext ‖ tag` in the FEC envelope (header also *inside* the
    /// FEC, SR-R1) → base64 (standard alphabet).
    ///
    /// # Parameters
    /// - `master`: the session master from [`derive_key`](Self::derive_key)
    ///   (HKDF-expanded internally — never a raw AES key).
    /// - `pt`: the plaintext bytes (`≤ `[`crate::MAX_PLAINTEXT_LEN`]).
    ///
    /// # Returns
    /// The base64-encoded blob.
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if `pt` exceeds the plaintext cap;
    /// [`CryptoError::KeyDerivation`] on HKDF failure; [`CryptoError::Cipher`] on
    /// nonce sampling or AEAD failure.
    // Byte core: the shared pipeline behind the public UTF-8 (Task 17) and
    // envelope (Task 18) front doors.
    fn encrypt_bytes(&self, master: &[u8], pt: &[u8]) -> Result<String> {
        // SR-R4: reject an over-cap plaintext before doing any work.
        if pt.len() > MAX_PLAINTEXT_LEN {
            return Err(CryptoError::InvalidInput(format!(
                "plaintext length {} exceeds MAX_PLAINTEXT_LEN ({MAX_PLAINTEXT_LEN})",
                pt.len()
            )));
        }
        // SR-C3: HKDF-expand the master into the AEAD sub-key.
        let aead_key = expand_aead_key(master)?;
        // SR-C1: a fresh per-record nonce from OsRng.
        let nonce = sample_nonce()?;
        // Header = version ‖ plaintext_len (LE): bound as AAD (SR-C4) and, via
        // encode_blob, also the first bytes of the FEC-protected payload (SR-R1).
        let plaintext_len = pt.len() as u32;
        let mut header = [0u8; HEADER_LEN];
        header[0] = BLOB_VERSION;
        header[1..].copy_from_slice(&plaintext_len.to_le_bytes());
        // SR-C4: encrypt with the header bound as additional authenticated data.
        let ct = self.cipher.encrypt(&aead_key, &nonce, &header, pt)?;
        // body = nonce ‖ ciphertext ‖ tag.
        let mut body = Vec::with_capacity(NONCE_LEN + ct.len());
        body.extend_from_slice(&nonce);
        body.extend_from_slice(&ct);
        // FEC-encode (header lives inside the FEC) then base64-encode.
        let blob = encode_blob(self.fec.as_ref(), BLOB_VERSION, plaintext_len, &body);
        Ok(STANDARD.encode(&blob))
    }

    /// Decrypts and verifies a base64 blob produced by
    /// [`encrypt_bytes`](Self::encrypt_bytes), returning the plaintext in a
    /// [`Zeroizing`] buffer (SR-C8, SR-R4/R6).
    ///
    /// **Pinned ordering (SR-R4/R6 safety-critical):** cap the base64 length
    /// *before* decode allocates (pre-allocation DoS guard) → strict base64
    /// decode → `decode_blob` (structural validation, FEC-correct, recover the
    /// error-corrected header) → reconstruct the AAD from the **recovered**
    /// header → AEAD-open. The AAD passed to open is always the error-corrected
    /// header, never a raw one.
    ///
    /// # Parameters
    /// - `master`: the session master from [`derive_key`](Self::derive_key).
    /// - `b64`: the base64 blob (`≤ `[`crate::MAX_B64_LEN`] characters).
    ///
    /// # Returns
    /// The recovered plaintext in a [`Zeroizing`] buffer (wiped on drop).
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if the base64 or decoded blob is oversized
    /// or structurally malformed; [`CryptoError::Encoding`] on non-canonical
    /// base64; [`CryptoError::ErrorCorrection`] beyond FEC capacity;
    /// [`CryptoError::Cipher`] if the AEAD tag fails (wrong master, wrong AAD, or
    /// tampering beyond FEC capacity). **Never panics** on adversarial input.
    // Byte core: see `encrypt_bytes`. Shared by the public UTF-8 / envelope
    // front doors.
    fn decrypt_bytes(&self, master: &[u8], b64: &str) -> Result<Zeroizing<Vec<u8>>> {
        // (1) SR-R4: cap the base64 length BEFORE base64-decode allocates.
        if b64.len() > MAX_B64_LEN {
            return Err(CryptoError::InvalidInput(format!(
                "base64 input length {} exceeds MAX_B64_LEN ({MAX_B64_LEN})",
                b64.len()
            )));
        }
        // (2) Strict base64 decode — the STANDARD engine rejects a bad alphabet,
        // non-canonical padding, and trailing bits.
        let decoded = STANDARD
            .decode(b64)
            .map_err(|e| CryptoError::Encoding(format!("base64 decode failed: {e}")))?;
        // (3) Structural validation + FEC-correct + recover the header (SR-R3/R6).
        let (version, plaintext_len, body) = decode_blob(self.fec.as_ref(), &decoded)?;
        // (4) SR-R6: reconstruct the AAD from the *error-corrected* header.
        let mut header = [0u8; HEADER_LEN];
        header[0] = version;
        header[1..].copy_from_slice(&plaintext_len.to_le_bytes());
        // body = nonce ‖ ciphertext ‖ tag. `decode_blob` guarantees
        // body.len() >= NONCE_LEN + TAG_LEN, but guard so no slice can panic.
        if body.len() < NONCE_LEN {
            return Err(CryptoError::InvalidInput(format!(
                "recovered body {} shorter than a {NONCE_LEN}-byte nonce",
                body.len()
            )));
        }
        let (nonce, ct) = body.split_at(NONCE_LEN);
        // (5) SR-C3/C4/C8: HKDF the AEAD key, open with the recovered header as
        // AAD, return the plaintext zeroized on drop.
        let aead_key = expand_aead_key(master)?;
        let pt = self.cipher.decrypt(&aead_key, nonce, &header, ct)?;
        Ok(Zeroizing::new(pt))
    }

    /// Encrypts and authenticates a UTF-8 string into a base64 blob — the public
    /// string front door over the byte core (SR-C1/C3/C4, SR-R4).
    ///
    /// A thin wrapper that treats `plaintext` as its UTF-8 bytes and runs the
    /// full AEAD-then-FEC pipeline; recover it with
    /// [`decrypt_with_key`](Self::decrypt_with_key).
    ///
    /// # Payload sizing (SR-F6)
    /// FEC recovery is **all-or-nothing per blob**: if channel corruption
    /// exceeds the concatenated code's capacity anywhere in the blob, the
    /// **whole** blob fails to decrypt (the AEAD needs the complete ciphertext).
    /// This cliff is **per-blob**, so on a noisy channel prefer **framing large
    /// data into multiple small blobs** — each blob then fails or recovers
    /// independently, and a single bad frame does not doom the rest. Very large
    /// single blobs are correspondingly more fragile.
    ///
    /// # Parameters
    /// - `key`: the session **master** from [`derive_key`](Self::derive_key)
    ///   (HKDF-expanded internally into the AEAD sub-key — never a raw AES key).
    /// - `plaintext`: the UTF-8 string to encrypt (its byte length must be
    ///   `≤ `[`crate::MAX_PLAINTEXT_LEN`]).
    ///
    /// # Returns
    /// The base64-encoded blob.
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if the plaintext exceeds the cap;
    /// [`CryptoError::KeyDerivation`] on HKDF failure; [`CryptoError::Cipher`] on
    /// nonce sampling or AEAD failure.
    ///
    /// # Examples
    /// ```
    /// use cryptovault::vault::CryptoVault;
    /// let vault = CryptoVault::default();
    /// let master = vault.derive_key("correct horse battery staple", &[0u8; 16]).unwrap();
    /// let blob = vault.encrypt_with_key(&master, "small message").unwrap();
    /// let plain = vault.decrypt_with_key(&master, &blob).unwrap();
    /// assert_eq!(&*plain, "small message");
    /// ```
    pub fn encrypt_with_key(&self, key: &[u8], plaintext: &str) -> Result<String> {
        self.encrypt_bytes(key, plaintext.as_bytes())
    }

    /// Decrypts and verifies a base64 blob produced by
    /// [`encrypt_with_key`](Self::encrypt_with_key), returning the recovered
    /// UTF-8 string in a [`Zeroizing`] buffer (SR-C8).
    ///
    /// Runs the byte core, then validates that the recovered plaintext is valid
    /// UTF-8; invalid UTF-8 is rejected rather than lossily decoded.
    ///
    /// # Parameters
    /// - `key`: the session master from [`derive_key`](Self::derive_key).
    /// - `blob`: the base64 blob (`≤ `[`crate::MAX_B64_LEN`] characters).
    ///
    /// # Returns
    /// The recovered string in a [`Zeroizing`] buffer (wiped on drop, SR-C8).
    ///
    /// # Errors
    /// [`CryptoError::Encoding`] if the base64 is non-canonical **or** the
    /// recovered plaintext is not valid UTF-8; [`CryptoError::InvalidInput`] on
    /// an oversized or structurally malformed blob;
    /// [`CryptoError::ErrorCorrection`] beyond FEC capacity;
    /// [`CryptoError::Cipher`] if the AEAD tag fails. **Never panics** on
    /// adversarial input.
    pub fn decrypt_with_key(&self, key: &[u8], blob: &str) -> Result<Zeroizing<String>> {
        let bytes = self.decrypt_bytes(key, blob)?;
        // Validate UTF-8 on the borrowed bytes; the transient `bytes` buffer is
        // zeroized on drop regardless of the branch taken.
        match core::str::from_utf8(&bytes) {
            Ok(s) => Ok(Zeroizing::new(s.to_owned())),
            Err(e) => Err(CryptoError::Encoding(format!(
                "decrypted plaintext is not valid UTF-8: {e}"
            ))),
        }
    }
}

impl Default for CryptoVault {
    /// Wires the audited defaults: Argon2id + AES-256-GCM-SIV + the concatenated
    /// FEC ([`ConcatenatedFec::default`]).
    fn default() -> Self {
        Self::new(
            Box::new(Argon2Kdf),
            Box::new(Aes256GcmSivCipher),
            Box::new(ConcatenatedFec::default()),
        )
    }
}

#[cfg(test)]
mod construction_tests {
    use super::{CryptoVault, NoFec};
    use crate::cipher::Aes256GcmSivCipher;
    use crate::error::CryptoError;
    use crate::fec::{ConcatenatedFec, ErrorCorrection};
    use crate::kdf::Argon2Kdf;
    use crate::{KEY_LEN, SALT_LEN};

    /// SR-C2 (+ OOP construction): `Default` wires the audited strategies, `new`
    /// injects them explicitly, `derive_key` produces a `KEY_LEN` master and
    /// rejects an empty password, and the vault is `Send + Sync`.
    #[test]
    fn test_sr_c2_default_wires_audited_impls_new_injects_and_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CryptoVault>();

        // Default = audited wiring.
        let v = CryptoVault::default();
        let m = v.derive_key("pw", &[0u8; SALT_LEN]).unwrap();
        assert_eq!(m.len(), KEY_LEN);

        // Empty password rejected.
        assert!(matches!(
            v.derive_key("", &[0u8; SALT_LEN]),
            Err(CryptoError::InvalidInput(_))
        ));

        // DI constructor injects strategies explicitly.
        let injected = CryptoVault::new(
            Box::new(Argon2Kdf),
            Box::new(Aes256GcmSivCipher),
            Box::new(ConcatenatedFec::default()),
        );
        assert_eq!(
            injected.derive_key("pw", &[0u8; SALT_LEN]).unwrap().len(),
            KEY_LEN
        );
    }

    /// SR-C2: `derive_key` rejects a wrong-length salt with `InvalidInput` rather
    /// than deriving from it (a wrong-length salt would silently weaken the KDF).
    #[test]
    fn test_sr_c2_derive_key_rejects_wrong_length_salt() {
        let v = CryptoVault::default();
        assert!(matches!(
            v.derive_key("pw", &[0u8; SALT_LEN - 1]),
            Err(CryptoError::InvalidInput(_))
        ));
        assert!(matches!(
            v.derive_key("pw", &[0u8; SALT_LEN + 1]),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    /// The AEAD-only fallback codec [`NoFec`] is an identity
    /// [`ErrorCorrection`]: `encode` returns the input unchanged and `decode`
    /// truncates the received bytes to `pre_len` — security preserved, channel
    /// resilience dropped.
    #[test]
    fn test_nofec_is_identity_encode_and_truncating_decode() {
        let data: Vec<u8> = (0..50u32).map(|i| i as u8).collect();
        assert_eq!(NoFec.encode(&data), data, "encode is identity");
        assert_eq!(
            NoFec.decode(&data, 20).unwrap(),
            data[..20],
            "decode truncates to pre_len"
        );
        // pre_len beyond the input length is clamped — never a slice panic.
        assert_eq!(NoFec.decode(&data, 999).unwrap(), data, "pre_len clamped");
    }
}

#[cfg(test)]
mod string_frontdoor_tests {
    use super::CryptoVault;
    use crate::error::CryptoError;
    use crate::KEY_LEN;

    /// SC-1 / SR-C8: a UTF-8 string encrypted then decrypted under the same
    /// master round-trips exactly through the public string front doors.
    #[test]
    fn test_sc1_encrypt_decrypt_with_key_roundtrip() {
        let v = CryptoVault::default();
        let master = [5u8; KEY_LEN];
        let plaintext = "café — attack at dawn, résilient over a noisy channel ✓";
        let blob = v.encrypt_with_key(&master, plaintext).unwrap();
        let recovered = v.decrypt_with_key(&master, &blob).unwrap();
        assert_eq!(&**recovered, plaintext, "string round-trip is exact");
    }

    /// SC-1: the empty string round-trips (degenerate but valid).
    #[test]
    fn test_sc1_empty_string_roundtrips() {
        let v = CryptoVault::default();
        let master = [1u8; KEY_LEN];
        let blob = v.encrypt_with_key(&master, "").unwrap();
        assert!(v.decrypt_with_key(&master, &blob).unwrap().is_empty());
    }

    /// SR-C8 / SR-F6: a blob whose recovered plaintext is not valid UTF-8 is
    /// rejected with a typed `Encoding` error rather than lossy/garbled text.
    #[test]
    fn test_sr_c8_decrypt_with_key_rejects_non_utf8_plaintext() {
        let v = CryptoVault::default();
        let master = [8u8; KEY_LEN];
        // 0xFF is never a valid UTF-8 byte; wrap it via the raw byte core.
        let blob = v.encrypt_bytes(&master, &[0xFF, 0xFE, 0x00]).unwrap();
        assert!(matches!(
            v.decrypt_with_key(&master, &blob),
            Err(CryptoError::Encoding(_))
        ));
    }

    /// SC-5: decrypting a string blob under a different master fails the AEAD
    /// tag with a typed `Cipher` error — no key material is revealed.
    #[test]
    fn test_sc5_decrypt_with_key_wrong_master_is_cipher_error() {
        let v = CryptoVault::default();
        let blob = v.encrypt_with_key(&[1u8; KEY_LEN], "secret text").unwrap();
        assert!(matches!(
            v.decrypt_with_key(&[2u8; KEY_LEN], &blob),
            Err(CryptoError::Cipher(_))
        ));
    }
}

#[cfg(test)]
mod byte_core_tests {
    use super::CryptoVault;
    use crate::error::CryptoError;
    use crate::{KEY_LEN, MAX_B64_LEN, MAX_PLAINTEXT_LEN};

    /// SC-1 / SR-C1: a plaintext encrypted then decrypted under the same master
    /// round-trips through the full AEAD + FEC + base64 pipeline exactly.
    #[test]
    fn test_sc1_encrypt_decrypt_bytes_roundtrip() {
        let v = CryptoVault::default();
        let master = [9u8; KEY_LEN];
        let pt = b"attack at dawn -- resilient over a noisy channel";
        let blob = v.encrypt_bytes(&master, pt).unwrap();
        let recovered = v.decrypt_bytes(&master, &blob).unwrap();
        assert_eq!(&*recovered, pt, "round-trip recovers the exact plaintext");
    }

    /// SC-1: the empty plaintext round-trips (degenerate but valid).
    #[test]
    fn test_sc1_empty_plaintext_roundtrips() {
        let v = CryptoVault::default();
        let master = [3u8; KEY_LEN];
        let blob = v.encrypt_bytes(&master, b"").unwrap();
        assert!(v.decrypt_bytes(&master, &blob).unwrap().is_empty());
    }

    /// SR-C1: two encryptions of the same plaintext differ — an independent
    /// `OsRng` nonce is sampled per record.
    #[test]
    fn test_sr_c1_two_encrypts_of_same_plaintext_differ() {
        let v = CryptoVault::default();
        let master = [7u8; KEY_LEN];
        let pt = b"same plaintext";
        let a = v.encrypt_bytes(&master, pt).unwrap();
        let b = v.encrypt_bytes(&master, pt).unwrap();
        assert_ne!(a, b, "independent nonce => distinct blobs");
    }

    /// SR-R4: a plaintext larger than `MAX_PLAINTEXT_LEN` is rejected with
    /// `InvalidInput` before any encryption work.
    #[test]
    fn test_sr_r4_encrypt_bytes_rejects_oversized_plaintext() {
        let v = CryptoVault::default();
        let master = [0u8; KEY_LEN];
        let oversized = vec![0u8; MAX_PLAINTEXT_LEN + 1];
        assert!(matches!(
            v.encrypt_bytes(&master, &oversized),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    /// SC-5: decrypting under a different master fails the AEAD tag with a typed
    /// `Cipher` error — no key material is revealed, never wrong plaintext.
    #[test]
    fn test_sc5_decrypt_bytes_wrong_master_is_cipher_error() {
        let v = CryptoVault::default();
        let blob = v.encrypt_bytes(&[1u8; KEY_LEN], b"top secret").unwrap();
        assert!(matches!(
            v.decrypt_bytes(&[2u8; KEY_LEN], &blob),
            Err(CryptoError::Cipher(_))
        ));
    }

    /// SR-R4: a base64 string longer than `MAX_B64_LEN` is rejected **before**
    /// base64-decode allocates — the pre-allocation DoS guard runs first.
    #[test]
    fn test_sr_r4_decrypt_bytes_rejects_giant_base64_pre_allocation() {
        let v = CryptoVault::default();
        let giant = "A".repeat(MAX_B64_LEN + 1);
        assert!(matches!(
            v.decrypt_bytes(&[0u8; KEY_LEN], &giant),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    /// SR-F6 / SC-6: non-canonical base64 (bad alphabet) is rejected with an
    /// `Encoding` error by the strict decoder, never silently accepted.
    #[test]
    fn test_sr_f6_non_canonical_base64_is_encoding_error() {
        let v = CryptoVault::default();
        // '*' is outside the standard base64 alphabet.
        assert!(matches!(
            v.decrypt_bytes(&[0u8; KEY_LEN], "****"),
            Err(CryptoError::Encoding(_))
        ));
    }
}
