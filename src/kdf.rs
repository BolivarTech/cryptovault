// Author: Julian Bolivar
// Version: 0.2.0
// Date: 2026-07-03
//! Key derivation: the `KeyDerivation` trait, the `Argon2Kdf` master-key
//! derivation, and HKDF sub-key expansion (SR-C2 / SR-C3).
//!
//! The master secret is derived once per session with memory-hard Argon2id
//! (SR-C2) and then split by HKDF-SHA256 domain separation into independent
//! purpose-specific sub-keys (SR-C3) — the interleaver seed is never the raw
//! AEAD key. All secret material is returned in [`Zeroizing`] buffers.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::KEY_LEN;

/// HKDF-SHA256 `info` label for the AEAD sub-key (SR-C3 domain separation).
const HKDF_INFO_AEAD: &[u8] = b"cryptovault:v1:aead";

/// HKDF-SHA256 `info` label for the interleaver-seed sub-key (SR-C3).
const HKDF_INFO_INTERLEAVER: &[u8] = b"cryptovault:v1:interleaver";

/// Strategy trait for deriving the 32-byte master secret from a passphrase and
/// a per-context salt (SR-C2).
///
/// Injectable so the audited [`Argon2Kdf`] default can be swapped for a test
/// double (e.g. a deterministic stub). Implementors MUST be `Send + Sync` so a
/// `CryptoVault` can derive across threads.
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
///
/// Crate-private (M5): [`argon2::Params`] is a third-party type, so exposing it
/// across the public boundary would make an `argon2` version bump a silent
/// public-API break (semver hazard). Nothing outside the crate needs it.
pub(crate) fn owasp_params() -> Params {
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
        let params = owasp_params();
        let block_count = params.block_count();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        // M2: own the ~64 MiB Argon2 working memory so it is wiped on drop. The
        // `argon2` crate otherwise frees this block buffer **unwiped** — its
        // final-column blocks are key-equivalent, so master-reconstructable
        // material would persist in freed heap. The `zeroize` feature makes
        // `Block: Zeroize`, so this `Zeroizing<Vec<Block>>` zeroizes every block
        // on drop (including on the error path below).
        let mut blocks = Zeroizing::new(vec![Block::default(); block_count]);
        let mut master = Zeroizing::new(vec![0u8; KEY_LEN]);
        argon2
            .hash_password_into_with_memory(password, salt, &mut master, blocks.as_mut_slice())
            .map_err(|e| CryptoError::KeyDerivation(format!("Argon2id derivation failed: {e}")))?;
        Ok(master)
    }
}

/// Expand the master secret into the 32-byte AES-256-GCM-SIV AEAD key
/// (SR-C3), using HKDF-SHA256 with `info = "cryptovault:v1:aead"`.
///
/// # Parameters
/// - `master`: the Argon2id master secret (see [`Argon2Kdf::derive_master`]).
///
/// # Returns
/// A [`Zeroizing`]-wrapped [`crate::KEY_LEN`]-byte AEAD key, distinct from the
/// raw master and from the interleaver seed (domain separation).
///
/// # Errors
/// [`CryptoError::KeyDerivation`] if the HKDF expand step fails (unreachable
/// for a [`crate::KEY_LEN`]-byte output, which is far below HKDF's `255 × 32`
/// limit).
pub fn expand_aead_key(master: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    hkdf_expand(master, HKDF_INFO_AEAD)
}

/// Expand the master secret into the 32-byte interleaver seed (SR-C3), using
/// HKDF-SHA256 with `info = "cryptovault:v1:interleaver"`.
///
/// This seed feeds **only** the optional CSPRNG interleaver layer; the default
/// deterministic block interleaver uses no key material. It is never the raw
/// AEAD key (distinct `info` label).
///
/// # Parameters
/// - `master`: the Argon2id master secret (see [`Argon2Kdf::derive_master`]).
///
/// # Returns
/// A [`Zeroizing`]-wrapped [`crate::KEY_LEN`]-byte interleaver seed.
///
/// # Errors
/// [`CryptoError::KeyDerivation`] if the HKDF expand step fails (unreachable for
/// a [`crate::KEY_LEN`]-byte output).
pub fn expand_interleaver_seed(master: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    hkdf_expand(master, HKDF_INFO_INTERLEAVER)
}

/// Shared HKDF-SHA256 expansion (DRY): derive one [`crate::KEY_LEN`]-byte
/// sub-key from `master` under the given `info` label.
///
/// # Errors
/// [`CryptoError::KeyDerivation`] if [`Hkdf::expand`] rejects the output length
/// (statically below the `255 × HashLen` HKDF cap, so unreachable here).
fn hkdf_expand(master: &[u8], info: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = Zeroizing::new(vec![0u8; KEY_LEN]);
    hk.expand(info, &mut out)
        .map_err(|e| CryptoError::KeyDerivation(format!("HKDF-SHA256 expand failed: {e}")))?;
    Ok(out)
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

    /// SR-F5 / SR-C2: the vault pins the OWASP-2025 Argon2id cost parameters
    /// (`m=64 MiB, t=3, p=4`, 32-byte output) and `derive_master` is
    /// deterministic. Migrated from `tests/kat.rs` (M5): `owasp_params` is now
    /// crate-private, so this pinning check lives as a unit test where it can name
    /// the function.
    #[test]
    fn test_sr_f5_argon2_owasp_params_pinned_and_deterministic() {
        let p = owasp_params();
        assert_eq!(
            (p.m_cost(), p.t_cost(), p.p_cost(), p.output_len()),
            (65536, 3, 4, Some(KEY_LEN)),
            "OWASP-2025 Argon2id parameters are pinned"
        );
        let a = Argon2Kdf
            .derive_master(b"kat-pw", &[0x11u8; SALT_LEN])
            .unwrap();
        let b = Argon2Kdf
            .derive_master(b"kat-pw", &[0x11u8; SALT_LEN])
            .unwrap();
        assert_eq!(&*a, &*b, "same password+salt → same master");
        assert_eq!(a.len(), KEY_LEN);
    }

    #[test]
    fn test_sr_c3_hkdf_domain_separation_distinct_and_deterministic() {
        let master = [7u8; KEY_LEN];
        let a = expand_aead_key(&master).unwrap();
        let s = expand_interleaver_seed(&master).unwrap();
        assert_eq!(a.len(), KEY_LEN);
        assert_ne!(&*a, &master, "seed must never equal raw master");
        assert_ne!(&*a, &*s, "domain separation: aead key != interleaver seed");
        assert_eq!(&*a, &*expand_aead_key(&master).unwrap()); // deterministic
    }
}
