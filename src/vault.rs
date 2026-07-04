// Author: Julian Bolivar
// Version: 0.2.1
// Date: 2026-07-03
//! Public facade: the `CryptoVault` composing the three strategy traits, plus
//! envelope key-wrapping and generation helpers (implemented in Tasks 15+,
//! SR-C5/C6/C8).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::blob::{decode_blob, encode_blob};
use crate::cipher::{sample_nonce, Aes256GcmSivCipher, AuthenticatedCipher};
use crate::error::{CryptoError, Result};
use crate::fec::{ConcatenatedFec, ErrorCorrection};
use crate::kdf::{expand_aead_key, Argon2Kdf, KeyDerivation};
use crate::{
    BLOB_VERSION, HEADER_LEN, KEY_LEN, MAX_B64_LEN, MAX_BLOB_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN,
    SALT_LEN,
};

/// AAD purpose label for the **data path** (`encrypt_bytes` / `encrypt_with_key`
/// / `decrypt_with_key`) — the first AAD byte (L9).
///
/// Domain-separates data-path blobs from envelope-path blobs so the two front
/// doors are **not cross-decryptable**, even under a matching key and empty
/// salt. The label is bound as AAD only (never stored in the blob).
const AAD_PURPOSE_DATA: u8 = 0x01;

/// AAD purpose label for the **envelope path** (`wrap_key` / `unwrap_key` /
/// `rewrap`) — the first AAD byte (L9). See [`AAD_PURPOSE_DATA`].
const AAD_PURPOSE_ENVELOPE: u8 = 0x02;

/// Generates a fresh per-context Argon2 salt: [`crate::SALT_LEN`] random bytes
/// from the operating-system CSPRNG (`OsRng`), in a [`Zeroizing`] buffer
/// (SR-C6).
///
/// Callers SHALL obtain every salt from this helper (never hand-rolled) so each
/// context gets a unique, high-entropy salt; salt uniqueness across contexts is
/// the caller's contract (reuse → same master → key collision).
///
/// # Returns
/// A [`Zeroizing`]-wrapped [`crate::SALT_LEN`]-byte salt (wiped on drop).
///
/// # Errors
/// [`CryptoError::KeyDerivation`] if `OsRng` fails to produce entropy — the salt
/// is **never** returned zero/weak and the function never panics (SR-C6 mirrors
/// the SR-C1 nonce contract).
pub fn generate_salt() -> Result<Zeroizing<Vec<u8>>> {
    random_zeroizing(SALT_LEN)
}

/// Generates a fresh data-encryption key (DEK): [`crate::KEY_LEN`] random bytes
/// from `OsRng`, in a [`Zeroizing`] buffer (SR-C6).
///
/// A one-way generator (no inverse) for the envelope DEK/KEK scheme; wrap the
/// returned DEK with [`CryptoVault::wrap_key`].
///
/// # Returns
/// A [`Zeroizing`]-wrapped [`crate::KEY_LEN`]-byte key (wiped on drop).
///
/// # Errors
/// [`CryptoError::KeyDerivation`] if `OsRng` fails to produce entropy — the key
/// is **never** returned zero/weak and the function never panics.
pub fn generate_dek() -> Result<Zeroizing<Vec<u8>>> {
    random_zeroizing(KEY_LEN)
}

/// Fills a [`Zeroizing`] buffer of `len` bytes from `OsRng` (DRY: shared by the
/// salt/DEK generators).
///
/// # Errors
/// [`CryptoError::KeyDerivation`] on an `OsRng` entropy failure — surfaced as a
/// typed error, never a panic and never a partially/zero-filled buffer.
fn random_zeroizing(len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; len]);
    OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| CryptoError::KeyDerivation(format!("OsRng entropy failure: {e}")))?;
    Ok(buf)
}

/// Compares two byte slices for equality in **constant time** with respect to
/// their content (SR-C7), for secret/tag comparisons where a data-dependent
/// early-exit would leak timing information.
///
/// Backed by [`subtle::ConstantTimeEq`]: slices of differing length compare
/// unequal, and equal-length slices are compared without a content-dependent
/// branch.
///
/// # Parameters
/// - `a` / `b`: the byte slices to compare (e.g. an expected vs. computed tag).
///
/// # Returns
/// `true` iff `a` and `b` have the same length and identical bytes.
///
/// # Examples
/// ```
/// use cryptovault::vault::constant_time_eq;
/// assert!(constant_time_eq(b"tag", b"tag"));
/// assert!(!constant_time_eq(b"tag", b"tab"));
/// ```
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

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

    /// Caps `received.len() <= `[`MAX_BLOB_LEN`] and returns it unchanged
    /// (SR-R4).
    ///
    /// A `NoFec` blob is the raw protected payload — there is **no** FEC framing
    /// to validate, so the whole received buffer is the pre-decode length. The
    /// allocation cap still applies so a hostile oversized blob is rejected
    /// before decode; never panics on adversarial input.
    fn validate_pre_fec(&self, received: &[u8]) -> Result<usize> {
        if received.len() > MAX_BLOB_LEN {
            return Err(CryptoError::InvalidInput(
                "input exceeds maximum size".into(),
            ));
        }
        Ok(received.len())
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
    /// Per-vault cap on the accepted **decoded** blob length (M3), enforced on
    /// the decrypt path before FEC decode. Defaults to [`MAX_BLOB_LEN`] and is
    /// clamped to it by [`with_max_blob_len`](Self::with_max_blob_len); a service
    /// can lower it to bound worst-case FEC-decode CPU for untrusted callers.
    max_blob_len: usize,
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
        Self {
            kdf,
            cipher,
            fec,
            max_blob_len: MAX_BLOB_LEN,
        }
    }

    /// Sets a per-vault cap on the accepted **decoded** blob length (M3),
    /// returning the reconfigured vault (builder style).
    ///
    /// The decrypt path rejects any received blob whose decoded length exceeds
    /// this cap **before** running the FEC decode, so a service can bound the
    /// worst-case FEC-decode CPU an untrusted caller can force with a single
    /// structurally-valid junk blob. `cap` is **clamped to [`MAX_BLOB_LEN`]** (the
    /// wire format never admits a larger blob); the default is [`MAX_BLOB_LEN`]
    /// (no extra restriction). This changes no wire format — it only tightens
    /// what this vault instance will accept on decode.
    ///
    /// # Parameters
    /// - `cap`: the maximum decoded blob length to accept (clamped to
    ///   [`MAX_BLOB_LEN`]).
    ///
    /// # Returns
    /// The vault with the tightened accept cap.
    #[must_use]
    pub fn with_max_blob_len(mut self, cap: usize) -> Self {
        self.max_blob_len = cap.min(MAX_BLOB_LEN);
        self
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
    /// # ⚠️ Resource-exhaustion / DoS surface (SR-C2)
    ///
    /// This call runs **memory-hard Argon2id** at the OWASP-2025 profile —
    /// **64 MiB of RAM plus CPU per call** — and is intended to run **once per
    /// session**. It is a resource-exhaustion / DoS surface: a service that
    /// exposes `derive_key` to untrusted callers **MUST rate-limit it** (each
    /// call costs 64 MiB + CPU, so unbounded invocation can exhaust memory/CPU).
    /// The per-record `encrypt_*` / `decrypt_*` / envelope paths use the cached
    /// master and do **not** re-run Argon2, so only this entry point carries the
    /// memory-hard cost.
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
                "salt must be exactly {SALT_LEN} bytes"
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
    // envelope (Task 18) front doors. Delegates to the AAD-extending variant
    // with no extra AAD (the non-envelope path binds the header only).
    fn encrypt_bytes(&self, master: &[u8], pt: &[u8]) -> Result<String> {
        self.encrypt_bytes_aad(master, pt, AAD_PURPOSE_DATA, &[])
    }

    /// Encrypts `pt` binding `header ‖ aad_extra` as the AEAD AAD — the shared
    /// byte core behind both the UTF-8 and envelope front doors (SR-C1/C3/C4,
    /// SR-R4). The non-envelope path passes an empty `aad_extra`; the envelope
    /// path passes the per-context salt so the wrapped material is
    /// cryptographically tied to its `(kek, salt)` context (SR-C5).
    ///
    /// Pipeline: bound the plaintext size (SR-R4) → HKDF-expand the AEAD sub-key
    /// (SR-C3) → sample a fresh nonce (SR-C1) → AES-256-GCM-SIV encrypt with
    /// `purpose ‖ version ‖ plaintext_len ‖ aad_extra` bound as **AAD** (L9 domain
    /// separation + SR-C4) → wrap
    /// `nonce ‖ ciphertext ‖ tag` in the FEC envelope (header also *inside* the
    /// FEC, SR-R1) → base64. `aad_extra` is authenticated but **never stored** in
    /// the blob (the salt stays caller-managed, out of band).
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if `pt` exceeds the plaintext cap;
    /// [`CryptoError::KeyDerivation`] on HKDF failure; [`CryptoError::Cipher`] on
    /// nonce sampling or AEAD failure.
    fn encrypt_bytes_aad(
        &self,
        master: &[u8],
        pt: &[u8],
        purpose: u8,
        aad_extra: &[u8],
    ) -> Result<String> {
        // M1: reject a wrong-length master before any work. HKDF accepts
        // any-length IKM, so without this an empty/truncated key would silently
        // produce a valid blob under a key derivable from nothing — one check
        // here covers all five public doors.
        if master.len() != KEY_LEN {
            return Err(CryptoError::InvalidInput(format!(
                "master key must be exactly {KEY_LEN} bytes"
            )));
        }
        // SR-R4: reject an over-cap plaintext before doing any work.
        if pt.len() > MAX_PLAINTEXT_LEN {
            return Err(CryptoError::InvalidInput(
                "plaintext exceeds maximum size".into(),
            ));
        }
        // SR-C3: HKDF-expand the master into the AEAD sub-key.
        let aead_key = expand_aead_key(master)?;
        // SR-C1: a fresh per-record nonce from OsRng.
        let nonce = sample_nonce()?;
        // Header = version ‖ plaintext_len (LE): bound as AAD (SR-C4) and, via
        // encode_blob, also the first bytes of the FEC-protected payload (SR-R1).
        let plaintext_len = pt.len() as u32;
        let header = Self::build_header(plaintext_len);
        // AAD = purpose ‖ header ‖ aad_extra (L9 domain separation + SR-C4 header
        // binding + SR-C5 salt binding).
        let aad = Self::build_aad(purpose, &header, aad_extra);
        // SR-C4/C5: encrypt with the header (+ optional salt) bound as AAD.
        let ct = self.cipher.encrypt(&aead_key, &nonce, &aad, pt)?;
        // body = nonce ‖ ciphertext ‖ tag.
        let mut body = Vec::with_capacity(NONCE_LEN + ct.len());
        body.extend_from_slice(&nonce);
        body.extend_from_slice(&ct);
        // FEC-encode (header lives inside the FEC) then base64-encode.
        let blob = encode_blob(self.fec.as_ref(), BLOB_VERSION, plaintext_len, &body);
        Ok(STANDARD.encode(&blob))
    }

    /// Builds the `version ‖ plaintext_len(LE)` blob header (DRY: shared by the
    /// encrypt and decrypt cores).
    fn build_header(plaintext_len: u32) -> [u8; HEADER_LEN] {
        let mut header = [0u8; HEADER_LEN];
        header[0] = BLOB_VERSION;
        header[1..].copy_from_slice(&plaintext_len.to_le_bytes());
        header
    }

    /// Concatenates the purpose label, header, and any extra AAD (the per-context
    /// salt) into the AEAD additional-authenticated-data buffer (DRY: shared by
    /// encrypt/decrypt).
    ///
    /// The leading `purpose` byte (L9) domain-separates the data path from the
    /// envelope path so their blobs are not cross-decryptable under a matching key
    /// and empty salt.
    fn build_aad(purpose: u8, header: &[u8; HEADER_LEN], aad_extra: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(1 + HEADER_LEN + aad_extra.len());
        aad.push(purpose);
        aad.extend_from_slice(header);
        aad.extend_from_slice(aad_extra);
        aad
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
    // Byte core: see `encrypt_bytes`. Delegates to the AAD-extending variant
    // with no extra AAD (the non-envelope path binds the header only).
    fn decrypt_bytes(&self, master: &[u8], b64: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.decrypt_bytes_aad(master, b64, AAD_PURPOSE_DATA, &[])
    }

    /// Decrypts a base64 blob binding `recovered_header ‖ aad_extra` as the AEAD
    /// AAD — the shared byte core behind the UTF-8 and envelope front doors
    /// (SR-C8, SR-R4/R6). The non-envelope path passes an empty `aad_extra`; the
    /// envelope path passes the per-context salt (SR-C5).
    ///
    /// **Pinned ordering (SR-R4/R6 safety-critical):** cap the base64 length
    /// *before* decode allocates (pre-allocation DoS guard) → strict base64
    /// decode → `decode_blob` (structural validation, FEC-correct, recover the
    /// error-corrected header) → reconstruct the AAD from the **recovered**
    /// header (+ `aad_extra`) → AEAD-open. The AAD passed to open is always built
    /// from the error-corrected header, never a raw one.
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if the base64 or decoded blob is oversized
    /// or structurally malformed; [`CryptoError::Encoding`] on non-canonical
    /// base64; [`CryptoError::ErrorCorrection`] beyond FEC capacity;
    /// [`CryptoError::Cipher`] if the AEAD tag fails (wrong master, wrong AAD/salt,
    /// or tampering beyond FEC capacity). **Never panics** on adversarial input.
    fn decrypt_bytes_aad(
        &self,
        master: &[u8],
        b64: &str,
        purpose: u8,
        aad_extra: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        // M1: reject a wrong-length master before any work (mirrors the encrypt
        // core) — the cipher's KEY_LEN check is otherwise bypassed by HKDF, which
        // accepts any-length IKM.
        if master.len() != KEY_LEN {
            return Err(CryptoError::InvalidInput(format!(
                "master key must be exactly {KEY_LEN} bytes"
            )));
        }
        // (1) SR-R4: cap the base64 length BEFORE base64-decode allocates.
        // N2/SR-R7: a fixed, generic message — the attacker's own input length is
        // never echoed back on the decode path.
        if b64.len() > MAX_B64_LEN {
            return Err(CryptoError::InvalidInput(
                "input exceeds maximum size".into(),
            ));
        }
        // (2) Strict base64 decode — the STANDARD engine rejects a bad alphabet,
        // non-canonical padding, and trailing bits.
        // SR-R7: map to a fixed, generic message — the base64 crate's error
        // interpolates the offending byte value / offset, a structural oracle the
        // decode path MUST NOT echo back to a probing caller.
        let decoded = STANDARD
            .decode(b64)
            .map_err(|_| CryptoError::Encoding("invalid encoding".into()))?;
        // (2b) M3: enforce the per-vault accept cap on the decoded blob BEFORE the
        // FEC decode, so an untrusted caller cannot force worst-case FEC-decode CPU
        // beyond this vault's configured bound (default MAX_BLOB_LEN).
        if decoded.len() > self.max_blob_len {
            return Err(CryptoError::InvalidInput(
                "input exceeds maximum size".into(),
            ));
        }
        // (3) Structural validation + FEC-correct + recover the header (SR-R3/R6).
        // `decode_blob` already validated the recovered version == BLOB_VERSION,
        // so the reconstructed header matches the error-corrected one.
        let (_version, plaintext_len, body) = decode_blob(self.fec.as_ref(), &decoded)?;
        // (4) SR-R6: reconstruct the AAD from the *error-corrected* header
        // (+ the caller-supplied salt for the envelope path, SR-C5).
        let header = Self::build_header(plaintext_len);
        let aad = Self::build_aad(purpose, &header, aad_extra);
        // body = nonce ‖ ciphertext ‖ tag. `decode_blob` guarantees
        // body.len() >= NONCE_LEN + TAG_LEN, but guard so no slice can panic.
        if body.len() < NONCE_LEN {
            // N2/SR-R7: fixed, generic message (this guard is statically
            // unreachable — `decode_blob` guarantees the body length — but keep the
            // message oracle-free for full decode-path consistency).
            return Err(CryptoError::InvalidInput("malformed blob".into()));
        }
        let (nonce, ct) = body.split_at(NONCE_LEN);
        // (5) SR-C3/C4/C8: HKDF the AEAD key, open with the recovered header (+
        // salt) as AAD, return the plaintext zeroized on drop.
        let aead_key = expand_aead_key(master)?;
        let pt = self.cipher.decrypt(&aead_key, nonce, &aad, ct)?;
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
    /// For reliable recovery keep each plaintext at or below
    /// [`RECOMMENDED_MAX_PAYLOAD`](crate::RECOMMENDED_MAX_PAYLOAD) (`128 KiB`) —
    /// the BER-derived practical ceiling (see `docs/ber-analysis.md`): at that
    /// size a blob recovers with probability ≈1.0 over the analyzed operating
    /// channel, with wide margin against the recovery waterfall. The absolute
    /// upper bound is [`MAX_PLAINTEXT_LEN`] (10 MiB),
    /// but blobs approaching it survive channel noise far less reliably; split
    /// large data into `RECOMMENDED_MAX_PAYLOAD`-sized frames.
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
    /// # ⚠️ Pre-authentication CPU cost (DoS surface)
    ///
    /// The **full FEC decode runs before the AEAD tag check**, so a hostile,
    /// structurally-valid junk blob (no valid key/tag) still forces the entire
    /// decode. Cost scales with blob size: **≈ 1.1 s at 128 KiB, ≈ 9 s at 1 MiB,
    /// ≈ 105 s at the 10 MiB cap** (single thread) — a ~24 MB max blob costs ~100 s
    /// of pre-authentication CPU. A service decrypting untrusted input **SHOULD
    /// rate-limit** and construct the vault with
    /// [`with_max_blob_len`](Self::with_max_blob_len) to bound worst-case decode
    /// latency below the 10 MiB absolute. See the crate-level operational
    /// constraints, the `# ⚠️ Memory` note above, and the
    /// [`derive_key`](Self::derive_key) DoS note.
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

    /// Wraps raw key material (a DEK) under a key-encryption key and per-context
    /// salt, returning a base64 envelope blob (SR-C5).
    ///
    /// Runs the same AEAD-then-FEC pipeline as [`encrypt_with_key`](Self::encrypt_with_key)
    /// but over **raw bytes** (not UTF-8) — the front door for envelope DEK/KEK
    /// key-wrapping. The per-context `salt` is bound as **AAD** (SR-C5), so a
    /// wrapped DEK is cryptographically tied to its `(kek, salt)` context: it can
    /// only be unwrapped by [`unwrap_key`](Self::unwrap_key) under the *same*
    /// salt, and rotated between contexts with [`rewrap`](Self::rewrap) (which
    /// binds the old and new salts). The salt is authenticated but **never
    /// stored** in the blob — it stays caller-managed, out of band.
    ///
    /// # Parameters
    /// - `kek`: the session **master** key-encryption key from
    ///   [`derive_key`](Self::derive_key) (HKDF-expanded internally).
    /// - `salt`: the per-context salt bound as AAD (typically the same salt used
    ///   to derive `kek`; pass `&[]` for no salt binding).
    /// - `key_material`: the raw DEK bytes to wrap (`≤ `[`crate::MAX_PLAINTEXT_LEN`]).
    ///
    /// # Returns
    /// The base64-encoded wrapped-key blob.
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if `key_material` exceeds the cap;
    /// [`CryptoError::KeyDerivation`] on HKDF failure; [`CryptoError::Cipher`] on
    /// nonce sampling or AEAD failure.
    pub fn wrap_key(&self, kek: &[u8], salt: &[u8], key_material: &[u8]) -> Result<String> {
        self.encrypt_bytes_aad(kek, key_material, AAD_PURPOSE_ENVELOPE, salt)
    }

    /// Unwraps a base64 envelope blob produced by [`wrap_key`](Self::wrap_key),
    /// returning the raw DEK in a [`Zeroizing`] buffer (SR-C5, SR-C8).
    ///
    /// The `salt` is bound as AAD and MUST match the one passed to
    /// [`wrap_key`](Self::wrap_key): a wrong `(kek, salt)` context fails the AEAD
    /// tag and reveals no key material (SR-C5).
    ///
    /// # ⚠️ Pre-authentication CPU cost (DoS surface)
    ///
    /// Like [`decrypt_with_key`](Self::decrypt_with_key), the **full FEC decode
    /// runs before the AEAD tag check**, so a hostile structurally-valid blob
    /// forces the entire decode regardless of key validity (**≈ 105 s at the
    /// 10 MiB cap**, single thread). A service unwrapping untrusted input **SHOULD
    /// rate-limit** and cap the accepted blob size via
    /// [`with_max_blob_len`](Self::with_max_blob_len). See the crate-level
    /// operational constraints and the `# ⚠️ Memory` note on [`CryptoVault`].
    ///
    /// # Parameters
    /// - `kek`: the master KEK from [`derive_key`](Self::derive_key) — the same
    ///   one passed to [`wrap_key`](Self::wrap_key).
    /// - `salt`: the per-context salt bound as AAD — the same one passed to
    ///   [`wrap_key`](Self::wrap_key) (pass `&[]` if none was bound).
    /// - `wrapped`: the base64 wrapped-key blob (`≤ `[`crate::MAX_B64_LEN`]).
    ///
    /// # Returns
    /// The recovered DEK bytes in a [`Zeroizing`] buffer (wiped on drop).
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] on an oversized/malformed blob;
    /// [`CryptoError::Encoding`] on non-canonical base64;
    /// [`CryptoError::ErrorCorrection`] beyond FEC capacity;
    /// [`CryptoError::Cipher`] if the AEAD tag fails (wrong KEK or salt) — **no
    /// key material is revealed**. **Never panics** on adversarial input.
    pub fn unwrap_key(&self, kek: &[u8], salt: &[u8], wrapped: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.decrypt_bytes_aad(kek, wrapped, AAD_PURPOSE_ENVELOPE, salt)
    }

    /// Re-wraps a salt-bound DEK from an old `(kek, salt)` context to a new one,
    /// rotating the key-encryption key without exposing the DEK (SR-C5).
    ///
    /// Unwraps `blob` under `(old_kek, old_salt)` — with `old_salt` bound as AAD
    /// so a mismatched old context fails the AEAD tag **before** any re-wrap —
    /// then re-wraps the recovered DEK under `(new_kek, new_salt)`. The
    /// intermediate DEK lives only transiently in a [`Zeroizing`] buffer (wiped
    /// on drop) and is **never logged**. No Argon2 runs on this path — both KEKs
    /// are pre-derived.
    ///
    /// # Parameters
    /// - `old_kek` / `old_salt`: the current context the DEK is bound to.
    /// - `new_kek` / `new_salt`: the target context to re-bind the DEK to.
    /// - `blob`: the base64 envelope blob bound to the old context.
    ///
    /// # Returns
    /// The base64-encoded DEK re-wrapped under the new context.
    ///
    /// # Errors
    /// [`CryptoError::Cipher`] if the old context does not authenticate (wrong
    /// `old_kek`/`old_salt`); plus any error from
    /// [`unwrap`](Self::unwrap_key)/[`wrap`](Self::wrap_key). **Never panics** on
    /// adversarial input.
    pub fn rewrap(
        &self,
        old_kek: &[u8],
        old_salt: &[u8],
        new_kek: &[u8],
        new_salt: &[u8],
        blob: &str,
    ) -> Result<String> {
        // Unwrap under the old context (old_salt bound as AAD); a wrong old
        // context fails the tag here, before any re-wrap. The DEK is Zeroizing.
        let dek = self.decrypt_bytes_aad(old_kek, blob, AAD_PURPOSE_ENVELOPE, old_salt)?;
        // Re-wrap the recovered DEK under the new context (new_salt as AAD).
        self.encrypt_bytes_aad(new_kek, &dek, AAD_PURPOSE_ENVELOPE, new_salt)
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

    /// C1 / SR-F4: a vault injected with the AEAD-only [`NoFec`] stack round-trips
    /// its own output through the **public API**. `NoFec` emits a raw (non-FEC)
    /// blob, so the decrypt path's structural validation must be delegated to the
    /// injected strategy — a hard-coded concatenated-FEC gate rejects a `NoFec`
    /// blob and breaks this documented injectable configuration.
    #[test]
    fn test_c1_nofec_vault_roundtrips_via_public_api() {
        let vault = CryptoVault::new(
            Box::new(Argon2Kdf),
            Box::new(Aes256GcmSivCipher),
            Box::new(NoFec),
        );
        let master = [0x5Au8; KEY_LEN];

        // UTF-8 string front door round-trips through a NoFec vault.
        let blob = vault.encrypt_with_key(&master, "small message").unwrap();
        let recovered = vault.decrypt_with_key(&master, &blob).unwrap();
        assert_eq!(&**recovered, "small message", "NoFec string round-trip");

        // Raw-byte envelope front door round-trips through a NoFec vault.
        let dek: Vec<u8> = (0..64u8).collect();
        let salt = [0x11u8; SALT_LEN];
        let wrapped = vault.wrap_key(&master, &salt, &dek).unwrap();
        let unwrapped = vault.unwrap_key(&master, &salt, &wrapped).unwrap();
        assert_eq!(&*unwrapped, &dek, "NoFec raw-byte round-trip");
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
mod generator_tests {
    use super::{constant_time_eq, generate_dek, generate_salt};
    use crate::{KEY_LEN, SALT_LEN};

    /// SR-C6: `generate_salt` returns exactly [`SALT_LEN`] bytes and yields a
    /// distinct value on each call (fresh `OsRng` entropy).
    #[test]
    fn test_sr_c6_generate_salt_correct_len_and_unique() {
        let a = generate_salt().unwrap();
        let b = generate_salt().unwrap();
        assert_eq!(a.len(), SALT_LEN, "salt is SALT_LEN bytes");
        assert_ne!(&*a, &*b, "two salts must differ (unique per call)");
    }

    /// SR-C6: `generate_dek` returns exactly [`KEY_LEN`] bytes and yields a
    /// distinct value on each call.
    #[test]
    fn test_sr_c6_generate_dek_correct_len_and_unique() {
        let a = generate_dek().unwrap();
        let b = generate_dek().unwrap();
        assert_eq!(a.len(), KEY_LEN, "dek is KEY_LEN bytes");
        assert_ne!(&*a, &*b, "two deks must differ (unique per call)");
    }

    /// SR-C7: the constant-time comparison agrees with logical equality —
    /// `true` for identical slices, `false` for differing content or length.
    #[test]
    fn test_sr_c7_constant_time_eq_matches_equality() {
        assert!(constant_time_eq(b"same tag", b"same tag"), "equal slices");
        assert!(!constant_time_eq(b"tag a", b"tag b"), "differing content");
        assert!(
            !constant_time_eq(b"short", b"longer tag"),
            "differing length"
        );
        assert!(constant_time_eq(b"", b""), "empty slices are equal");
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
mod envelope_tests {
    use super::CryptoVault;
    use crate::error::CryptoError;
    use crate::{KEY_LEN, SALT_LEN};

    /// SC-7 / SR-C5: raw key material (the full `0..=255` byte range, never valid
    /// UTF-8) wraps and unwraps under the same KEK exactly.
    #[test]
    fn test_sc7_wrap_unwrap_raw_bytes_roundtrip() {
        let v = CryptoVault::default();
        let kek = [4u8; KEY_LEN];
        let salt = [7u8; SALT_LEN];
        let dek: Vec<u8> = (0..=255u16).map(|b| b as u8).collect();
        let wrapped = v.wrap_key(&kek, &salt, &dek).unwrap();
        let unwrapped = v.unwrap_key(&kek, &salt, &wrapped).unwrap();
        assert_eq!(&*unwrapped, &dek, "raw byte round-trip is exact");
    }

    /// SC-7: empty key material is a valid degenerate wrap/unwrap.
    #[test]
    fn test_sc7_wrap_unwrap_empty_material() {
        let v = CryptoVault::default();
        let kek = [6u8; KEY_LEN];
        let salt = [5u8; SALT_LEN];
        let wrapped = v.wrap_key(&kek, &salt, b"").unwrap();
        assert!(v.unwrap_key(&kek, &salt, &wrapped).unwrap().is_empty());
    }

    /// L9: the data path and the envelope path bind distinct purpose labels into
    /// the AAD, so a blob made by `encrypt_with_key` cannot be opened by
    /// `unwrap_key` (and vice-versa) even under a matching key and empty salt —
    /// while same-door round-trips still succeed.
    #[test]
    fn test_l9_data_and_envelope_blobs_are_not_cross_decryptable() {
        let v = CryptoVault::default();
        let key = [0x33u8; KEY_LEN];

        // A data-path blob does not unwrap via the envelope door (empty salt).
        let data_blob = v.encrypt_with_key(&key, "hello").unwrap();
        assert!(matches!(
            v.unwrap_key(&key, &[], &data_blob),
            Err(CryptoError::Cipher(_))
        ));
        // An envelope-path blob does not decrypt via the data door.
        let env_blob = v.wrap_key(&key, &[], b"hello").unwrap();
        assert!(matches!(
            v.decrypt_with_key(&key, &env_blob),
            Err(CryptoError::Cipher(_))
        ));
        // Same-door round-trips still pass.
        assert_eq!(&**v.decrypt_with_key(&key, &data_blob).unwrap(), "hello");
        assert_eq!(&*v.unwrap_key(&key, &[], &env_blob).unwrap(), b"hello");
    }

    /// SC-5: unwrapping under the wrong KEK fails the AEAD tag with a typed
    /// `Cipher` error and reveals no key material.
    #[test]
    fn test_sc5_unwrap_wrong_kek_is_cipher_error() {
        let v = CryptoVault::default();
        let salt = [3u8; SALT_LEN];
        let wrapped = v.wrap_key(&[1u8; KEY_LEN], &salt, b"a dek").unwrap();
        assert!(matches!(
            v.unwrap_key(&[2u8; KEY_LEN], &salt, &wrapped),
            Err(CryptoError::Cipher(_))
        ));
    }

    /// C2 / SR-C5: the **public** envelope API composes end-to-end —
    /// `wrap_key(kek, salt, dek)` binds the per-context salt as AAD, so
    /// `wrap → rewrap → unwrap_key` chains through the public surface: the new
    /// context recovers the exact DEK and the old context no longer unwraps the
    /// rewrapped blob.
    #[test]
    fn test_c2_public_wrap_rewrap_unwrap_chain() {
        let v = CryptoVault::default();
        let (old_kek, new_kek) = ([1u8; KEY_LEN], [9u8; KEY_LEN]);
        let (old_salt, new_salt) = ([2u8; SALT_LEN], [3u8; SALT_LEN]);
        let dek: Vec<u8> = (0..64u8).collect();

        // Public wrap binds (old_kek, old_salt).
        let wrapped = v.wrap_key(&old_kek, &old_salt, &dek).unwrap();
        // Rotate to the new context.
        let rewrapped = v
            .rewrap(&old_kek, &old_salt, &new_kek, &new_salt, &wrapped)
            .unwrap();
        // The NEW context recovers the exact DEK through the public unwrap.
        let recovered = v.unwrap_key(&new_kek, &new_salt, &rewrapped).unwrap();
        assert_eq!(
            &*recovered, &dek,
            "public wrap→rewrap→unwrap recovers the DEK"
        );
        // The OLD context no longer unwraps the rewrapped blob.
        assert!(
            matches!(
                v.unwrap_key(&old_kek, &old_salt, &rewrapped),
                Err(CryptoError::Cipher(_))
            ),
            "old context must not unwrap the rewrapped blob"
        );
    }

    /// SC-7 / SR-C5: `rewrap` re-binds a salt-bound DEK from the old context to a
    /// new `(kek, salt)`; the new context unwraps it, the old context no longer
    /// does (its salt AAD no longer matches).
    #[test]
    fn test_sc7_rewrap_rebinds_context_old_no_longer_unwraps() {
        let v = CryptoVault::default();
        let (old_kek, new_kek) = ([1u8; KEY_LEN], [9u8; KEY_LEN]);
        let (old_salt, new_salt) = ([2u8; SALT_LEN], [3u8; SALT_LEN]);
        let dek: Vec<u8> = (0..64u8).collect();

        // Initial blob bound to the OLD context via the PUBLIC wrap (kek + salt
        // as AAD).
        let wrapped = v.wrap_key(&old_kek, &old_salt, &dek).unwrap();

        // Re-tie old → new context.
        let rewrapped = v
            .rewrap(&old_kek, &old_salt, &new_kek, &new_salt, &wrapped)
            .unwrap();

        // New context recovers the exact DEK through the public unwrap.
        let recovered = v.unwrap_key(&new_kek, &new_salt, &rewrapped).unwrap();
        assert_eq!(&*recovered, &dek, "rewrap preserves the DEK");

        // Old context (old kek + old salt) no longer unwraps the rewrapped blob.
        assert!(matches!(
            v.unwrap_key(&old_kek, &old_salt, &rewrapped),
            Err(CryptoError::Cipher(_))
        ));
    }

    /// SR-C5: `rewrap` under the wrong old context (mismatched `old_salt`) fails
    /// the AEAD tag before any re-wrap — a typed `Cipher` error, no DEK exposed.
    #[test]
    fn test_sc5_rewrap_wrong_old_salt_is_cipher_error() {
        let v = CryptoVault::default();
        let (old_kek, new_kek) = ([1u8; KEY_LEN], [9u8; KEY_LEN]);
        let (old_salt, new_salt) = ([2u8; SALT_LEN], [3u8; SALT_LEN]);
        let wrapped = v.wrap_key(&old_kek, &old_salt, b"dek").unwrap();
        assert!(matches!(
            v.rewrap(&old_kek, &[0u8; SALT_LEN], &new_kek, &new_salt, &wrapped),
            Err(CryptoError::Cipher(_))
        ));
    }
}

#[cfg(test)]
mod byte_core_tests {
    use super::CryptoVault;
    use crate::error::CryptoError;
    use crate::{KEY_LEN, MAX_B64_LEN, MAX_PLAINTEXT_LEN};

    /// M1 (SR-C*): the byte cores reject a master that is not exactly `KEY_LEN`
    /// bytes. An empty or truncated key must fail with `InvalidInput` on both the
    /// encrypt and decrypt cores (covering all five public doors), never silently
    /// encrypt under a key HKDF-derivable from nothing.
    #[test]
    fn test_m1_byte_cores_reject_wrong_length_master() {
        let v = CryptoVault::default();
        // Empty and short keys are rejected on the encrypt core.
        assert!(matches!(
            v.encrypt_with_key(&[], "x"),
            Err(CryptoError::InvalidInput(_))
        ));
        assert!(matches!(
            v.encrypt_with_key(&[0u8; KEY_LEN - 1], "x"),
            Err(CryptoError::InvalidInput(_))
        ));
        // A correct-length key still works; its blob rejects an empty key on the
        // decrypt core.
        let blob = v.encrypt_with_key(&[0u8; KEY_LEN], "x").unwrap();
        assert!(matches!(
            v.decrypt_with_key(&[], &blob),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    /// M3: a per-vault `max_blob_len` cap (default `MAX_BLOB_LEN`, clamped) lets a
    /// service bound worst-case FEC-decode CPU. A vault with a small cap rejects a
    /// blob whose decoded length exceeds the cap with `InvalidInput`, while the
    /// default vault still round-trips the same blob. No wire-format change.
    #[test]
    fn test_m3_per_vault_max_blob_len_cap_rejects_oversized_blob() {
        let master = [0x11u8; KEY_LEN];
        let default_vault = CryptoVault::default();
        let blob = default_vault
            .encrypt_bytes(&master, b"payload to protect")
            .unwrap();
        // Default vault (cap = MAX_BLOB_LEN) round-trips the blob.
        assert_eq!(
            &*default_vault.decrypt_bytes(&master, &blob).unwrap(),
            b"payload to protect"
        );
        // A vault with a tiny cap rejects the same, larger, blob before FEC decode.
        let capped = CryptoVault::default().with_max_blob_len(64);
        assert!(matches!(
            capped.decrypt_bytes(&master, &blob),
            Err(CryptoError::InvalidInput(_))
        ));
    }

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

    /// N2 (SR-R7): the pre-cap base64-length rejection uses a fixed, generic
    /// message that does not echo the attacker's own input length back.
    #[test]
    fn test_n2_giant_base64_rejection_message_is_generic() {
        let v = CryptoVault::default();
        let giant = "A".repeat(MAX_B64_LEN + 1);
        match v.decrypt_bytes(&[0u8; KEY_LEN], &giant) {
            Err(CryptoError::InvalidInput(msg)) => {
                assert_eq!(msg, "input exceeds maximum size");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
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
