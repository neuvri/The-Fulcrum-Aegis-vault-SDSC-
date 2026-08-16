// =============================================================================
//  AEGIS SOVEREIGN VAULT — v9.2  |  INTEGRATION TESTS
//  Pipeline: encrypt → decrypt → verify content + hash integrity.
//
//  Coverage:
//    ✅ Full roundtrip — byte-for-byte content + hash integrity
//    ✅ Shred: original deleted, vault survives
//    ✅ Wrong password → Auth error, partial output cleaned up
//    ✅ Tampered vault → Crypto/Tamper error detected
//    ✅ Large file (1 MiB) roundtrip
//    ✅ Empty file roundtrip
//    ✅ Missing file → Io error (encrypt + decrypt)
//    ✅ Shamir: threshold recovery (any 3-of-5)
//    ✅ Shamir: below-threshold fails
//    ✅ Shamir: non-consecutive share set
//    ✅ Different passwords → different ciphertext
//    ✅ Audit identifier: deterministic for same key, unique per password
// =============================================================================

use aegis_vault::crypto::{
    async_decrypt, async_encrypt, compute_file_hash, generate_recovery_shares,
    recover_key_from_shares, AegisError, MasterKey, SHAMIR_THRESHOLD, SHAMIR_TOTAL,
};
use secrecy::SecretVec;
use std::sync::Arc;
use tempfile::tempdir;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn pw(s: &[u8]) -> Arc<SecretVec<u8>> {
    Arc::new(SecretVec::new(s.to_vec()))
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
}

// =============================================================================
//  1. Full roundtrip — content + hash integrity
// =============================================================================

#[test]
fn full_roundtrip_content_integrity() {
    rt().block_on(async {
        let dir = tempdir().unwrap();
        let plain = dir.path().join("data.bin");
        let original =
            "The Fulcrum — AEGIS Sovereign Vault v9.2 integration test payload 12345".as_bytes();
        std::fs::write(&plain, original).unwrap();

        let hash_before = compute_file_hash(&plain).await.unwrap();

        let password = pw(b"strong-integration-passphrase!");
        let (msg, shares, audit_id) = async_encrypt(
            Arc::clone(&password),
            plain.to_str().unwrap().to_string(),
            false,
        )
        .await
        .unwrap();

        assert!(msg.contains("Encrypted"), "encrypt msg: {msg}");
        assert_eq!(shares.len(), SHAMIR_TOTAL);
        assert!(!audit_id.is_empty());

        let vault = dir.path().join("data.bin.aegis");
        assert!(vault.exists(), ".aegis must be created");

        let msg2 = async_decrypt(Arc::clone(&password), vault.to_str().unwrap().to_string())
            .await
            .unwrap();
        assert!(msg2.contains("opened"), "decrypt msg: {msg2}");

        // Byte-for-byte content
        let recovered = std::fs::read(&plain).unwrap();
        assert_eq!(
            recovered.as_slice(),
            original,
            "content mismatch after decrypt"
        );

        // SHA-256 hash
        let hash_after = compute_file_hash(&plain).await.unwrap();
        assert_eq!(hash_before, hash_after, "hash mismatch after decrypt");
    });
}

// =============================================================================
//  2. Shred: original deleted, vault survives
// =============================================================================

#[test]
fn shred_deletes_original_and_keeps_vault() {
    rt().block_on(async {
        let dir = tempdir().unwrap();
        let plain = dir.path().join("sensitive.txt");
        std::fs::write(&plain, b"top-secret payload").unwrap();

        async_encrypt(
            pw(b"shred-passphrase-2024"),
            plain.to_str().unwrap().to_string(),
            true,
        )
        .await
        .unwrap();

        assert!(!plain.exists(), "original must be securely deleted");
        assert!(
            dir.path().join("sensitive.txt.aegis").exists(),
            ".aegis must exist"
        );
    });
}

// =============================================================================
//  3. Wrong password → Auth error + partial output cleaned up
// =============================================================================

#[test]
fn wrong_password_returns_auth_error() {
    rt().block_on(async {
        let dir = tempdir().unwrap();
        let plain = dir.path().join("secret.bin");
        std::fs::write(&plain, b"confidential data").unwrap();

        let correct = pw(b"correct-passphrase-2024!");
        let wrong = pw(b"wrong-passphrase-2024-xx");

        async_encrypt(
            Arc::clone(&correct),
            plain.to_str().unwrap().to_string(),
            true,
        )
        .await
        .unwrap();

        let vault = dir.path().join("secret.bin.aegis");
        let err = async_decrypt(wrong, vault.to_str().unwrap().to_string())
            .await
            .unwrap_err();

        assert!(
            matches!(err, AegisError::Auth),
            "wrong password must return Auth, got: {err}"
        );
        // The original was shredded after encryption; a failed decrypt with the
        // wrong password must not resurrect any plaintext at the output path.
        assert!(
            !plain.exists(),
            "partial plaintext must not survive a failed decrypt"
        );
    });
}

// =============================================================================
//  4. Tampered vault → detected
// =============================================================================

#[test]
fn tampered_ciphertext_is_detected() {
    rt().block_on(async {
        let dir = tempdir().unwrap();
        let plain = dir.path().join("tamper.bin");
        std::fs::write(&plain, b"tamper detection test data 1234").unwrap();

        let password = pw(b"tamper-test-passphrase-2024");
        async_encrypt(
            Arc::clone(&password),
            plain.to_str().unwrap().to_string(),
            false,
        )
        .await
        .unwrap();

        let vault = dir.path().join("tamper.bin.aegis");
        let mut data = std::fs::read(&vault).unwrap();
        let flip_at = data.len() * 3 / 4;
        data[flip_at] ^= 0xFF;
        std::fs::write(&vault, &data).unwrap();

        let err = async_decrypt(Arc::clone(&password), vault.to_str().unwrap().to_string())
            .await
            .unwrap_err();

        assert!(
            matches!(
                err,
                AegisError::Crypto(_) | AegisError::Tamper | AegisError::Auth
            ),
            "tampered vault must be detected, got: {err}"
        );
    });
}

// =============================================================================
//  5. Large file (1 MiB) roundtrip
// =============================================================================

#[test]
fn large_file_roundtrip_1mib() {
    rt().block_on(async {
        let dir = tempdir().unwrap();
        let plain = dir.path().join("large.bin");
        let data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
        std::fs::write(&plain, &data).unwrap();

        let hash_before = compute_file_hash(&plain).await.unwrap();
        let password = pw(b"large-file-passphrase-2024!");

        async_encrypt(
            Arc::clone(&password),
            plain.to_str().unwrap().to_string(),
            true,
        )
        .await
        .unwrap();

        let vault = dir.path().join("large.bin.aegis");
        async_decrypt(Arc::clone(&password), vault.to_str().unwrap().to_string())
            .await
            .unwrap();

        let hash_after = compute_file_hash(&plain).await.unwrap();
        assert_eq!(
            hash_before, hash_after,
            "1 MiB hash must match after roundtrip"
        );
    });
}

// =============================================================================
//  6. Empty file roundtrip
// =============================================================================

#[test]
fn empty_file_roundtrip() {
    rt().block_on(async {
        let dir = tempdir().unwrap();
        let plain = dir.path().join("empty.bin");
        std::fs::write(&plain, b"").unwrap();

        let password = pw(b"empty-file-passphrase-2024!");
        async_encrypt(
            Arc::clone(&password),
            plain.to_str().unwrap().to_string(),
            false,
        )
        .await
        .unwrap();

        let vault = dir.path().join("empty.bin.aegis");
        async_decrypt(Arc::clone(&password), vault.to_str().unwrap().to_string())
            .await
            .unwrap();

        let recovered = std::fs::read(&plain).unwrap();
        assert!(recovered.is_empty(), "empty file must roundtrip correctly");
    });
}

// =============================================================================
//  7. Encrypt missing file → Io error
// =============================================================================

#[test]
fn encrypt_missing_file_returns_io_error() {
    rt().block_on(async {
        let err = async_encrypt(
            pw(b"irrelevant-password-here"),
            "/nonexistent/path/missing.bin".to_string(),
            false,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, AegisError::Io(_)),
            "missing file must give Io error: {err}"
        );
    });
}

// =============================================================================
//  8. Decrypt missing vault → Io error
// =============================================================================

#[test]
fn decrypt_missing_vault_returns_io_error() {
    rt().block_on(async {
        let err = async_decrypt(
            pw(b"irrelevant-password-here"),
            "/nonexistent/missing.aegis".to_string(),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, AegisError::Io(_)),
            "missing vault must give Io error: {err}"
        );
    });
}

// =============================================================================
//  9. Shamir: exactly threshold shares recovers key
// =============================================================================

#[test]
fn shamir_threshold_recovery_succeeds() {
    let key = [0xDEu8; 32];
    let shares = generate_recovery_shares(&key).unwrap();
    assert_eq!(shares.len(), SHAMIR_TOTAL);

    let recovered = recover_key_from_shares(&shares[..SHAMIR_THRESHOLD]).unwrap();
    assert_eq!(
        recovered, key,
        "exactly-threshold shares must recover the key"
    );
}

// =============================================================================
//  10. Shamir: below threshold → error
// =============================================================================

#[test]
fn shamir_below_threshold_fails() {
    let key = [0xEFu8; 32];
    let shares = generate_recovery_shares(&key).unwrap();

    let err = recover_key_from_shares(&shares[..SHAMIR_THRESHOLD - 1]);
    assert!(err.is_err(), "below-threshold shares must fail");
}

// =============================================================================
//  11. Shamir: non-consecutive subset (shares 1, 3, 5)
// =============================================================================

#[test]
fn shamir_non_consecutive_subset() {
    let key = [0xABu8; 32];
    let shares = generate_recovery_shares(&key).unwrap();

    let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
    let recovered = recover_key_from_shares(&subset).unwrap();
    assert_eq!(
        recovered, key,
        "non-consecutive shares [1,3,5] must recover the key"
    );
}

// =============================================================================
//  12. Different passwords → different ciphertexts
// =============================================================================

#[test]
fn different_passwords_produce_different_ciphertext() {
    rt().block_on(async {
        let dir = tempdir().unwrap();
        let content = b"identical content, different keys";

        let p1 = dir.path().join("f1.bin");
        let p2 = dir.path().join("f2.bin");
        std::fs::write(&p1, content).unwrap();
        std::fs::write(&p2, content).unwrap();

        async_encrypt(
            pw(b"password-alpha-12345"),
            p1.to_str().unwrap().to_string(),
            false,
        )
        .await
        .unwrap();
        async_encrypt(
            pw(b"password-beta-67890x"),
            p2.to_str().unwrap().to_string(),
            false,
        )
        .await
        .unwrap();

        let ct1 = std::fs::read(dir.path().join("f1.bin.aegis")).unwrap();
        let ct2 = std::fs::read(dir.path().join("f2.bin.aegis")).unwrap();
        assert_ne!(
            ct1, ct2,
            "same content + different passwords must produce different ciphertext"
        );
    });
}

// =============================================================================
//  13. Audit identifier: deterministic for same key material
// =============================================================================

#[test]
fn audit_id_is_deterministic_for_same_key() {
    let pw_bytes = b"deterministic-pw-2024-aegis";
    let salt = [0x55u8; 32];
    let mk1 = MasterKey::derive(pw_bytes, &salt, 64, 1, 1).unwrap();
    let mk2 = MasterKey::derive(pw_bytes, &salt, 64, 1, 1).unwrap();
    assert_eq!(
        mk1.audit_identifier(),
        mk2.audit_identifier(),
        "same password+salt must produce same audit ID"
    );
}

// =============================================================================
//  14. Audit identifier: unique per password
// =============================================================================

#[test]
fn audit_id_differs_per_password() {
    let salt = [0x77u8; 32];
    let mk1 = MasterKey::derive(b"password-one-long-2024", &salt, 64, 1, 1).unwrap();
    let mk2 = MasterKey::derive(b"password-two-long-2024", &salt, 64, 1, 1).unwrap();
    assert_ne!(
        mk1.audit_identifier(),
        mk2.audit_identifier(),
        "different passwords must produce different audit IDs"
    );
}

// =============================================================================
//  15. Two sequential encryptions of same file → different vaults (random nonce)
// =============================================================================

#[test]
fn same_file_twice_produces_different_vaults() {
    rt().block_on(async {
        let dir = tempdir().unwrap();
        let p1 = dir.path().join("copy1.bin");
        let p2 = dir.path().join("copy2.bin");
        let content = b"nonce randomness test payload";

        std::fs::write(&p1, content).unwrap();
        std::fs::write(&p2, content).unwrap();

        let password = pw(b"same-password-for-both-12345");
        async_encrypt(
            Arc::clone(&password),
            p1.to_str().unwrap().to_string(),
            false,
        )
        .await
        .unwrap();
        async_encrypt(
            Arc::clone(&password),
            p2.to_str().unwrap().to_string(),
            false,
        )
        .await
        .unwrap();

        let ct1 = std::fs::read(dir.path().join("copy1.bin.aegis")).unwrap();
        let ct2 = std::fs::read(dir.path().join("copy2.bin.aegis")).unwrap();
        // Different random salt+nonce → different ciphertext every time
        assert_ne!(
            ct1, ct2,
            "same password + same plaintext must still produce different ciphertext (random nonce)"
        );
    });
}
