// Author: Julian Bolivar
// Version: 2.0.0
// Date: 2026-07-03
//! Typed error domain for the vault: the single `CryptoError` enum and its
//! `Result` alias (implemented in Task 1, SR-R7).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sr_r7_error_variants_display_and_are_typed() {
        let e = CryptoError::InvalidInput("bad len".into());
        assert!(e.to_string().to_lowercase().contains("invalid"));
        assert!(matches!(e, CryptoError::InvalidInput(_)));
    }
}
