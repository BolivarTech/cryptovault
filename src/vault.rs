// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Public facade: the `CryptoVault` composing the three strategy traits, plus
//! envelope key-wrapping and generation helpers (implemented in Tasks 15+,
//! SR-C5/C6/C8).

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
