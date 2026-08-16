// =============================================================================
//  AEGIS SOVEREIGN VAULT — v9.1  |  LIBRARY ROOT
// =============================================================================

pub mod audit;
pub mod biometrics;
pub mod crypto;
pub mod dashboard;
pub mod lto;
pub mod sync;

// =============================================================================
//  SHARED: Audit key validation (single source of truth)
// =============================================================================

pub fn get_audit_key_from_env() -> Result<[u8; 32], String> {
    let hex_key = std::env::var("AEGIS_AUDIT_KEY").map_err(|_| {
        "AEGIS_AUDIT_KEY is not set.\n  \
         Generate: openssl rand -hex 32\n  \
         Then:     export AEGIS_AUDIT_KEY=<value>"
            .to_string()
    })?;

    let bytes = hex::decode(&hex_key)
        .map_err(|_| "AEGIS_AUDIT_KEY must be valid hex (64 hex chars = 32 bytes)".to_string())?;

    if bytes.len() != 32 {
        return Err(format!(
            "AEGIS_AUDIT_KEY must be 32 bytes (64 hex chars), got: {} bytes",
            bytes.len()
        ));
    }

    if bytes.iter().all(|&b| b == 0) {
        return Err(
            "AEGIS_AUDIT_KEY must not be all zeros — generate a real key:\n  \
             openssl rand -hex 32"
                .to_string(),
        );
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

// =============================================================================
//  TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn set_key(val: &str) {
        std::env::set_var("AEGIS_AUDIT_KEY", val);
    }
    fn clear_key() {
        std::env::remove_var("AEGIS_AUDIT_KEY");
    }

    #[test]
    fn valid_key_accepted() {
        set_key("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2");
        assert!(get_audit_key_from_env().is_ok());
        clear_key();
    }

    #[test]
    fn missing_key_rejected() {
        clear_key();
        let err = get_audit_key_from_env().unwrap_err();
        assert!(err.contains("not set"));
    }

    #[test]
    fn zero_key_rejected() {
        set_key(&"00".repeat(32));
        let err = get_audit_key_from_env().unwrap_err();
        assert!(err.contains("all zeros"));
        clear_key();
    }

    #[test]
    fn short_key_rejected() {
        set_key("deadbeef");
        let err = get_audit_key_from_env().unwrap_err();
        assert!(err.contains("bytes"));
        clear_key();
    }

    #[test]
    fn invalid_hex_rejected() {
        set_key(&"zz".repeat(32));
        let err = get_audit_key_from_env().unwrap_err();
        assert!(err.contains("hex"));
        clear_key();
    }

    #[test]
    fn key_has_correct_length() {
        set_key("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2");
        let key = get_audit_key_from_env().unwrap();
        assert_eq!(key.len(), 32);
        clear_key();
    }
}
