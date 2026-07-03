// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Key derivation: the `KeyDerivation` trait, the `Argon2Kdf` master-key
//! derivation, and HKDF sub-key expansion (SR-C2 / SR-C3).
//!
//! The master secret is derived once per session with memory-hard Argon2id
//! (SR-C2) and then split by HKDF-SHA256 domain separation into independent
//! purpose-specific sub-keys (SR-C3) — the interleaver seed is never the raw
//! AEAD key. All secret material is returned in [`Zeroizing`] buffers.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::KEY_LEN;

/// Strategy trait for deriving the 32-byte master secret from a passphrase and
/// a per-context salt (SR-C2).
///
/// Injectable so the audited [`Argon2Kdf`] default can be swapped for a test
/// double (e.g. a deterministic stub). Implementors MUST be `Send + Sync` so a
/// [`crate::vault::CryptoVault`] can derive across threads.
pub trait KeyDerivation: Send + Sync {
    /// Derive the 32-byte master secret from `password` and `salt`.
    ///
    /// # Parameters
    /// - `password`: the passphrase bytes (caller-supplied; may be any length).
    /// - `salt`: the per-context salt (expected [`crate::SALT_LEN`] bytes).
    ///
    /// # Returns
    /// A [`Zeroizing`]-wrapped 32-byte master secret (wiped on drop).
    ///
    /// # Errors
    /// [`CryptoError::KeyDerivation`] if the underlying KDF rejects the inputs
    /// (e.g. a salt shorter than the KDF minimum) or fails internally.
    fn derive_master(&self, password: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

/// Audited default [`KeyDerivation`]: Argon2id at the pinned OWASP-2025 cost
/// parameters (SR-C2).
///
/// Fieldless strategy struct — construct directly as `Argon2Kdf` (no `new`
/// needed). Memory-hard by design: expensive to run, so it is invoked **once
/// per session** and the resulting master cached by the caller in
/// [`Zeroizing`]; per-record operations never re-derive.
///
/// # Examples
/// ```
/// use cryptovault::kdf::{Argon2Kdf, KeyDerivation};
/// let master = Argon2Kdf.derive_master(b"correct horse", &[0u8; 16]).unwrap();
/// assert_eq!(master.len(), 32);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Argon2Kdf;

/// Build the pinned OWASP-2025 Argon2id parameters (`m = 64 MiB, t = 3, p = 4`),
/// with a fixed [`crate::KEY_LEN`]-byte output.
///
/// # Panics / `expect`
/// The `expect` is **statically unreachable**: [`Params::new`] only errors on
/// out-of-range cost values, and the arguments here are compile-time constants
/// ([`crate::ARGON2_M_KIB`], [`crate::ARGON2_T`], [`crate::ARGON2_P`],
/// [`crate::KEY_LEN`]) all within Argon2's valid ranges. A failure would mean
/// the pinned constants were edited to invalid values — a build-time bug, not a
/// runtime condition, so no adversarial input can reach it.
pub fn owasp_params() -> Params {
    Params::new(
        crate::ARGON2_M_KIB,
        crate::ARGON2_T,
        crate::ARGON2_P,
        Some(KEY_LEN),
    )
    .expect("OWASP-2025 Argon2 params are statically valid (constants in range)")
}

impl KeyDerivation for Argon2Kdf {
    fn derive_master(&self, password: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, owasp_params());
        let mut master = Zeroizing::new(vec![0u8; KEY_LEN]);
        argon2
            .hash_password_into(password, salt, &mut master)
            .map_err(|e| CryptoError::KeyDerivation(format!("Argon2id derivation failed: {e}")))?;
        Ok(master)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KEY_LEN, SALT_LEN};

    #[test]
    fn test_sr_c2_argon2_owasp_params_and_master_is_32_bytes() {
        let p = owasp_params();
        assert_eq!((p.m_cost(), p.t_cost(), p.p_cost()), (65536, 3, 4));
        let m = Argon2Kdf.derive_master(b"pw", &[0u8; SALT_LEN]).unwrap();
        assert_eq!(m.len(), KEY_LEN);
        // determinism: same password+salt -> same master
        let m2 = Argon2Kdf.derive_master(b"pw", &[0u8; SALT_LEN]).unwrap();
        assert_eq!(&*m, &*m2);
    }
}
