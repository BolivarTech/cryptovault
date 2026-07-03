// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Key derivation: the `KeyDerivation` trait, the `Argon2Kdf` master-key
//! derivation, and HKDF sub-key expansion (implemented in Tasks 2-3, SR-C2/C3).

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
