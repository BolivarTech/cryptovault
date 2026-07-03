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
