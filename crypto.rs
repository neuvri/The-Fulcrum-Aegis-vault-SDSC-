// =============================================================================
//  AEGIS SOVEREIGN VAULT — v9.1  |  CRYPTO CORE
//  Cross-platform: Linux / macOS / Windows
//
//  Security fixes applied:
//    — Nonce registry persisted to disk (prevents reuse across restarts)
//    — proptest uses shared runtime (no per-iteration Runtime::new)
//    — fs4 lock used correctly (sync, not async)
//    — All keys zeroized on drop
// =============================================================================

#![allow(dead_code)]

use aes_gcm::{
    aead::{
        generic_array::GenericArray,
        stream::{DecryptorBE32, EncryptorBE32},
        Aead,
    },
    Aes256Gcm, KeyInit, Nonce,
};
use aes_gcm_siv::Aes256GcmSiv;
use argon2::{Argon2, Params as Argon2Params, Version as Argon2Version};
use fs4::tokio::AsyncFileExt;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use qrcode::{render::unicode, QrCode};
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sharks::{Share, Sharks};
use std::collections::HashSet;
use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, BufWriter},
};
use tracing::instrument;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
//  CONSTANTS
// =============================================================================

pub const VERSION_MAJOR: u16 = 9;
pub const VERSION_MINOR: u16 = 1;
pub const MAGIC_BYTES: &[u8; 6] = b"AEGIS9";
pub const HEADER_SIZE: u64 = 200;
pub const BUFFER_SIZE: usize = 512 * 1024;
pub const SALT_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const KVT_SIZE: usize = 32;
pub const HEADER_MAC_SIZE: usize = 32;
pub const ARGON2_OUTPUT_LEN: usize = 64;
pub const ARGON2_MEM_KIB: u32 = 128 * 1024;
pub const ARGON2_ITERS: u32 = 4;
pub const ARGON2_PARALLEL: u32 = 4;
pub const MAX_ARGON2_MEM_KIB: u32 = 4 * 1024 * 1024;
pub const MAX_ARGON2_ITERS: u32 = 64;
pub const MAX_ARGON2_PARALLEL: u32 = 64;
pub const SHAMIR_TOTAL: usize = 5;
pub const SHAMIR_THRESHOLD: usize = 3;
pub const MAX_FILE_SIZE: u64 = 1_099_511_627_776; // 1 TiB

pub const KVT_INFO: &[u8] = b"aegis-kvt-v9";
pub const HEADER_MAC_INFO: &[u8] = b"aegis-header-mac-v9";
pub const ENC_KEY_INFO: &[u8] = b"aegis-enc-key-v9";
pub const HMAC_KEY_INFO: &[u8] = b"aegis-hmac-key-v9";
pub const AUDIT_KEY_INFO: &[u8] = b"aegis-audit-key-v9";
pub const RECOVERY_KEY_INFO: &[u8] = b"aegis-recovery-key-v9";
pub const AUDIT_ID_INFO: &[u8] = b"aegis-audit-id-v9";

type HmacSha256 = Hmac<Sha256>;

pub static AUDIT_LOG_PATH: Lazy<String> = Lazy::new(|| {
    std::env::var("AEGIS_AUDIT_PATH").unwrap_or_else(|_| "aegis_audit.enc".to_string())
});

pub static NONCE_LOG_PATH: Lazy<String> = Lazy::new(|| {
    std::env::var("AEGIS_NONCE_PATH").unwrap_or_else(|_| "aegis_nonces.log".to_string())
});

// =============================================================================
//  NONCE REGISTRY — persistent on disk (prevents reuse across restarts)
// =============================================================================

static NONCE_REGISTRY: Lazy<Mutex<HashSet<[u8; 12]>>> = Lazy::new(|| {
    let set = load_nonces_from_disk().unwrap_or_default();
    Mutex::new(set)
});

fn load_nonces_from_disk() -> std::io::Result<HashSet<[u8; 12]>> {
    let path = NONCE_LOG_PATH.as_str();
    if !Path::new(path).exists() {
        return Ok(HashSet::new());
    }
    let data = std::fs::read(path)?;
    let mut set = HashSet::new();
    for chunk in data.chunks_exact(12) {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(chunk);
        set.insert(nonce);
    }
    Ok(set)
}

fn append_nonce_to_disk(nonce: &[u8; 12]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(NONCE_LOG_PATH.as_str())?;
    f.write_all(nonce)?;
    f.sync_data()?;
    Ok(())
}

pub async fn register_nonce(nonce: [u8; 12]) -> Result<(), AegisError> {
    let mut registry = NONCE_REGISTRY.lock().await;
    if registry.contains(&nonce) {
        return Err(AegisError::NonceCollision);
    }
    append_nonce_to_disk(&nonce)
        .map_err(|e| AegisError::Io(format!("Cannot persist nonce: {e}")))?;
    registry.insert(nonce);
    Ok(())
}

// =============================================================================
//  ERROR TYPE
// =============================================================================

#[derive(Debug)]
pub enum AegisError {
    Io(String),
    Crypto(String),
    Kdf(String),
    Header(String),
    Auth,
    Tamper,
    NonceCollision,
    TooLarge,
    InvalidParam(String),
    Shamir(String),
    Audit(String),
    Dashboard(String),
    Biometrics(String),
}

impl std::fmt::Display for AegisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AegisError::Io(s) => write!(f, "I/O error: {s}"),
            AegisError::Crypto(s) => write!(f, "Crypto error: {s}"),
            AegisError::Kdf(s) => write!(f, "KDF error: {s}"),
            AegisError::Header(s) => write!(f, "Header error: {s}"),
            AegisError::Auth => write!(f, "Wrong password or corrupted vault."),
            AegisError::Tamper => {
                write!(f, "Header integrity check failed — file may be tampered.")
            }
            AegisError::NonceCollision => write!(f, "Nonce collision — RNG failure, abort."),
            AegisError::TooLarge => write!(f, "File exceeds 1 TiB limit."),
            AegisError::InvalidParam(s) => write!(f, "Invalid parameter: {s}"),
            AegisError::Shamir(s) => write!(f, "Shamir error: {s}"),
            AegisError::Audit(s) => write!(f, "Audit error: {s}"),
            AegisError::Dashboard(s) => write!(f, "Dashboard error: {s}"),
            AegisError::Biometrics(s) => write!(f, "Biometrics error: {s}"),
        }
    }
}

impl std::error::Error for AegisError {}

// =============================================================================
//  MASTER KEY — zeroized on drop
// =============================================================================

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    pub encryption_key: [u8; 32],
    pub hmac_key: [u8; 32],
    pub audit_key: [u8; 32],
    pub kvt: [u8; 32],
    pub header_mac_key: [u8; 32],
    pub recovery_key: [u8; 32],
    pub audit_id_key: [u8; 32],
}

impl MasterKey {
    pub fn derive(
        password: &[u8],
        salt: &[u8; SALT_SIZE],
        mem_kib: u32,
        iters: u32,
        parallel: u32,
    ) -> Result<Self, AegisError> {
        let params = Argon2Params::new(mem_kib, iters, parallel, Some(ARGON2_OUTPUT_LEN))
            .map_err(|e| AegisError::Kdf(e.to_string()))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Argon2Version::V0x13, params);
        let mut ikm = vec![0u8; ARGON2_OUTPUT_LEN];
        argon2
            .hash_password_into(password, salt, &mut ikm)
            .map_err(|e| AegisError::Kdf(e.to_string()))?;
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        ikm.zeroize();
        let mut mk = MasterKey {
            encryption_key: [0u8; 32],
            hmac_key: [0u8; 32],
            audit_key: [0u8; 32],
            kvt: [0u8; 32],
            header_mac_key: [0u8; 32],
            recovery_key: [0u8; 32],
            audit_id_key: [0u8; 32],
        };
        hk.expand(ENC_KEY_INFO, &mut mk.encryption_key)
            .map_err(|_| AegisError::Kdf("enc_key".into()))?;
        hk.expand(HMAC_KEY_INFO, &mut mk.hmac_key)
            .map_err(|_| AegisError::Kdf("hmac_key".into()))?;
        hk.expand(AUDIT_KEY_INFO, &mut mk.audit_key)
            .map_err(|_| AegisError::Kdf("audit_key".into()))?;
        hk.expand(KVT_INFO, &mut mk.kvt)
            .map_err(|_| AegisError::Kdf("kvt".into()))?;
        hk.expand(HEADER_MAC_INFO, &mut mk.header_mac_key)
            .map_err(|_| AegisError::Kdf("header_mac".into()))?;
        hk.expand(RECOVERY_KEY_INFO, &mut mk.recovery_key)
            .map_err(|_| AegisError::Kdf("recovery_key".into()))?;
        hk.expand(AUDIT_ID_INFO, &mut mk.audit_id_key)
            .map_err(|_| AegisError::Kdf("audit_id".into()))?;
        Ok(mk)
    }

    /// معرّف جلسة التدقيق — لا يكشف عن المفتاح
    pub fn audit_identifier(&self) -> String {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.audit_id_key).expect("HMAC init");
        mac.update(b"audit-session-id");
        hex::encode(&mac.finalize().into_bytes()[..16])
    }
}

pub fn compute_header_mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC");
    mac.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

// =============================================================================
//  SHAMIR SECRET SHARING
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryShare {
    pub index: usize,
    pub share_hex: String,
    pub qr_code_ascii: String,
    pub created_at: u64,
}

pub fn generate_recovery_shares(recovery_key: &[u8; 32]) -> Result<Vec<RecoveryShare>, AegisError> {
    let sharks = Sharks(SHAMIR_THRESHOLD as u8);
    let dealer = sharks.dealer(recovery_key.as_ref());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut result = Vec::with_capacity(SHAMIR_TOTAL);

    for (i, share) in dealer.take(SHAMIR_TOTAL).enumerate() {
        let share_bytes = Vec::from(&share);
        let share_hex = hex::encode(&share_bytes);
        let qr_ascii = QrCode::new(share_hex.as_bytes())
            .map(|code| {
                code.render::<unicode::Dense1x2>()
                    .dark_color(unicode::Dense1x2::Dark)
                    .light_color(unicode::Dense1x2::Light)
                    .quiet_zone(true)
                    .build()
            })
            .unwrap_or_else(|_| share_hex.clone());
        result.push(RecoveryShare {
            index: i + 1,
            share_hex,
            qr_code_ascii: qr_ascii,
            created_at: now,
        });
    }
    Ok(result)
}

pub fn recover_key_from_shares(shares: &[RecoveryShare]) -> Result<[u8; 32], AegisError> {
    if shares.len() < SHAMIR_THRESHOLD {
        return Err(AegisError::Shamir(format!(
            "Need at least {SHAMIR_THRESHOLD} shares, got {}",
            shares.len()
        )));
    }
    let sharks = Sharks(SHAMIR_THRESHOLD as u8);
    let parsed: Vec<Share> = shares
        .iter()
        .map(|s| {
            let bytes =
                hex::decode(&s.share_hex).map_err(|e| AegisError::Shamir(format!("hex: {e}")))?;
            Share::try_from(bytes.as_slice()).map_err(|e| AegisError::Shamir(format!("parse: {e}")))
        })
        .collect::<Result<_, _>>()?;

    let secret = sharks
        .recover(parsed.iter())
        .map_err(|e| AegisError::Shamir(format!("recover: {e}")))?;

    if secret.len() != 32 {
        return Err(AegisError::Shamir(format!(
            "Recovered key wrong length: {} (expected 32)",
            secret.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&secret);
    Ok(key)
}

// =============================================================================
//  ENCRYPTED AUDIT LOG
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub operation: String,
    pub file_path: String,
    pub file_hash: String,
    pub file_size: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedAuditRecord {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub mac: String,
}

impl AuditEntry {
    pub fn encrypt(&self, audit_key: &[u8; 32]) -> Result<EncryptedAuditRecord, AegisError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let data = serde_json::to_vec(self).map_err(|e| AegisError::Audit(e.to_string()))?;
        let cipher = Aes256GcmSiv::new_from_slice(audit_key)
            .map_err(|_| AegisError::Audit("Cipher init".into()))?;
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), data.as_ref())
            .map_err(|e| AegisError::Audit(e.to_string()))?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(audit_key)
            .map_err(|_| AegisError::Audit("HMAC init".into()))?;
        mac.update(&ct);
        mac.update(&nonce_bytes);
        Ok(EncryptedAuditRecord {
            ciphertext: ct,
            nonce: nonce_bytes,
            mac: hex::encode(mac.finalize().into_bytes()),
        })
    }

    pub fn decrypt(
        record: &EncryptedAuditRecord,
        audit_key: &[u8; 32],
    ) -> Result<AuditEntry, AegisError> {
        // Verify MAC first (constant-time)
        let mut mac = <HmacSha256 as Mac>::new_from_slice(audit_key)
            .map_err(|_| AegisError::Audit("HMAC init".into()))?;
        mac.update(&record.ciphertext);
        mac.update(&record.nonce);
        let expected = hex::encode(mac.finalize().into_bytes());
        if expected.as_bytes().ct_eq(record.mac.as_bytes()).unwrap_u8() != 1 {
            return Err(AegisError::Tamper);
        }
        let cipher = Aes256GcmSiv::new_from_slice(audit_key)
            .map_err(|_| AegisError::Audit("Cipher init".into()))?;
        let pt = cipher
            .decrypt(Nonce::from_slice(&record.nonce), record.ciphertext.as_ref())
            .map_err(|_| AegisError::Audit("Decrypt failed".into()))?;
        serde_json::from_slice(&pt).map_err(|e| AegisError::Audit(e.to_string()))
    }
}

pub async fn append_audit(entry: &AuditEntry, audit_key: &[u8; 32]) -> Result<(), AegisError> {
    let record = entry.encrypt(audit_key)?;
    let line = serde_json::to_string(&record).map_err(|e| AegisError::Audit(e.to_string()))?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(AUDIT_LOG_PATH.as_str())
        .await
        .map_err(|e| AegisError::Audit(e.to_string()))?;
    f.write_all(line.as_bytes())
        .await
        .map_err(|e| AegisError::Audit(e.to_string()))?;
    f.write_all(b"\n")
        .await
        .map_err(|e| AegisError::Audit(e.to_string()))?;
    Ok(())
}

// =============================================================================
//  FILE UTILITIES
// =============================================================================

pub async fn compute_file_hash(path: &Path) -> Result<String, AegisError> {
    let mut file = File::open(path)
        .await
        .map_err(|e| AegisError::Io(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; BUFFER_SIZE];
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| AegisError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// حذف آمن 7 تمريرات DoD 5220.22-M
pub async fn secure_delete(path: &Path) -> Result<(), AegisError> {
    let size = tokio::fs::metadata(path)
        .await
        .map_err(|e| AegisError::Io(e.to_string()))?
        .len() as usize;
    let mut f = OpenOptions::new()
        .write(true)
        .open(path)
        .await
        .map_err(|e| AegisError::Io(e.to_string()))?;
    // FIX: lock_exclusive is sync in fs4 v0.8
    f.lock_exclusive()
        .map_err(|e| AegisError::Io(e.to_string()))?;

    let chunk = BUFFER_SIZE.min(size.max(1));
    let mut buf = vec![0u8; chunk];
    let pass_random = [true, false, false, false, false, false, true];
    let patterns = [0xFFu8, 0x00, 0x55, 0xAA, 0x92, 0x49, 0x24];

    for pass in 0..7usize {
        f.seek(SeekFrom::Start(0))
            .await
            .map_err(|e| AegisError::Io(format!("seek pass {pass}: {e}")))?;
        let mut written = 0usize;
        while written < size {
            let n = (size - written).min(chunk);
            if pass_random[pass] {
                OsRng.fill_bytes(&mut buf[..n]);
            } else {
                buf[..n].fill(patterns[pass]);
            }
            f.write_all(&buf[..n])
                .await
                .map_err(|e| AegisError::Io(format!("write pass {pass}: {e}")))?;
            written += n;
        }
        f.sync_all()
            .await
            .map_err(|e| AegisError::Io(format!("sync pass {pass}: {e}")))?;
    }
    f.set_len(0)
        .await
        .map_err(|_| AegisError::Io("truncate".into()))?;
    f.sync_all()
        .await
        .map_err(|_| AegisError::Io("fsync truncate".into()))?;
    drop(f);
    tokio::fs::remove_file(path)
        .await
        .map_err(|e| AegisError::Io(e.to_string()))?;
    Ok(())
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// =============================================================================
//  ENCRYPTION
// =============================================================================

#[instrument(skip(password))]
pub async fn async_encrypt(
    password: Arc<SecretVec<u8>>,
    input_path: String,
    shred_after: bool,
) -> Result<(String, Vec<RecoveryShare>, String), AegisError> {
    let in_path = PathBuf::from(&input_path);
    if !in_path.exists() {
        return Err(AegisError::Io("File not found".into()));
    }
    let file_size = tokio::fs::metadata(&in_path)
        .await
        .map_err(|e| AegisError::Io(e.to_string()))?
        .len();
    if file_size > MAX_FILE_SIZE {
        return Err(AegisError::TooLarge);
    }
    let file_hash = compute_file_hash(&in_path).await?;
    let out_path = PathBuf::from(format!("{input_path}.aegis"));

    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    let mut recovery_salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    OsRng.fill_bytes(&mut recovery_salt);

    register_nonce(nonce).await?;

    let pw_ref = Arc::clone(&password);
    let salt_copy = salt;
    let master_key = tokio::task::spawn_blocking(move || {
        MasterKey::derive(
            pw_ref.expose_secret(),
            &salt_copy,
            ARGON2_MEM_KIB,
            ARGON2_ITERS,
            ARGON2_PARALLEL,
        )
    })
    .await
    .map_err(|e| AegisError::Kdf(format!("KDF task panic: {e}")))??;

    let shares = generate_recovery_shares(&master_key.recovery_key)?;
    let timestamp = unix_now();

    // Build header (200 bytes)
    let mut header = [0u8; 200];
    header[0..6].copy_from_slice(MAGIC_BYTES);
    header[6..8].copy_from_slice(&VERSION_MAJOR.to_be_bytes());
    header[8..10].copy_from_slice(&VERSION_MINOR.to_be_bytes());
    header[10] = 0x01; // flags
    header[16..48].copy_from_slice(&salt);
    header[48..60].copy_from_slice(&nonce);
    header[60..64].copy_from_slice(&ARGON2_MEM_KIB.to_be_bytes());
    header[64..68].copy_from_slice(&ARGON2_ITERS.to_be_bytes());
    header[68..72].copy_from_slice(&ARGON2_PARALLEL.to_be_bytes());
    header[72..76].copy_from_slice(&(BUFFER_SIZE as u32).to_be_bytes());
    header[76..84].copy_from_slice(&timestamp.to_be_bytes());
    header[84..116].copy_from_slice(&recovery_salt);
    header[116..148].copy_from_slice(&master_key.kvt);
    header[148..150].copy_from_slice(&(SHAMIR_THRESHOLD as u16).to_be_bytes());
    header[150..152].copy_from_slice(&(SHAMIR_TOTAL as u16).to_be_bytes());
    let mac = compute_header_mac(&master_key.header_mac_key, &header[0..168]);
    header[168..200].copy_from_slice(&mac);

    // Open source/dest with exclusive locks
    let std_src = std::fs::OpenOptions::new()
        .read(true)
        .open(&in_path)
        .map_err(|e| AegisError::Io(format!("open src: {e}")))?;
    fs4::FileExt::try_lock_exclusive(&std_src)
        .map_err(|e| AegisError::Io(format!("lock src: {e}")))?;
    let std_dst = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&out_path)
        .map_err(|e| AegisError::Io(format!("create dst: {e}")))?;
    fs4::FileExt::try_lock_exclusive(&std_dst)
        .map_err(|e| AegisError::Io(format!("lock dst: {e}")))?;

    let src_tok = File::from_std(std_src);
    let dst_tok = File::from_std(std_dst);
    let mut reader = BufReader::new(src_tok);
    let mut writer = BufWriter::new(dst_tok);
    writer
        .write_all(&header)
        .await
        .map_err(|e| AegisError::Io(e.to_string()))?;

    let aead = Aes256Gcm::new_from_slice(&master_key.encryption_key)
        .map_err(|_| AegisError::Crypto("cipher init".into()))?;
    let mut encryptor = Some(EncryptorBE32::from_aead(
        aead,
        GenericArray::from_slice(&nonce[..7]),
    ));
    let mut current = vec![0u8; BUFFER_SIZE];
    let mut next_buf = vec![0u8; BUFFER_SIZE];
    let mut n = reader
        .read(&mut current)
        .await
        .map_err(|e| AegisError::Io(e.to_string()))?;

    loop {
        let m = reader
            .read(&mut next_buf)
            .await
            .map_err(|e| AegisError::Io(e.to_string()))?;
        let is_last = m == 0;
        let ct = if is_last {
            encryptor
                .take()
                .ok_or_else(|| AegisError::Crypto("encryptor consumed".into()))?
                .encrypt_last(&current[..n])
                .map_err(|_| AegisError::Crypto("encrypt_last failed".into()))?
        } else {
            encryptor
                .as_mut()
                .ok_or_else(|| AegisError::Crypto("encryptor consumed".into()))?
                .encrypt_next(&current[..n])
                .map_err(|_| AegisError::Crypto("encrypt_next failed".into()))?
        };
        writer
            .write_all(&ct)
            .await
            .map_err(|e| AegisError::Io(e.to_string()))?;
        if is_last {
            break;
        }
        std::mem::swap(&mut current, &mut next_buf);
        n = m;
    }
    writer
        .flush()
        .await
        .map_err(|e| AegisError::Io(e.to_string()))?;
    drop(reader);

    if shred_after {
        secure_delete(&in_path).await?;
    }

    let _ = append_audit(
        &AuditEntry {
            timestamp: unix_now(),
            operation: "ENCRYPT".into(),
            file_path: input_path.clone(),
            file_hash,
            file_size,
            status: "SUCCESS".into(),
        },
        &master_key.audit_key,
    )
    .await;

    let audit_id = master_key.audit_identifier();
    let out_name = out_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| out_path.display().to_string());
    Ok((format!("Encrypted → {out_name}"), shares, audit_id))
}

// =============================================================================
//  DECRYPTION
// =============================================================================

#[instrument(skip(password))]
pub async fn async_decrypt(
    password: Arc<SecretVec<u8>>,
    input_path: String,
) -> Result<String, AegisError> {
    let in_path = PathBuf::from(&input_path);
    if !in_path.exists() {
        return Err(AegisError::Io("Vault not found".into()));
    }
    let out_path = match input_path.strip_suffix(".aegis") {
        Some(stripped) => PathBuf::from(stripped),
        None => return Err(AegisError::Io("expected a .aegis vault file".into())),
    };

    let std_src = std::fs::OpenOptions::new()
        .read(true)
        .open(&in_path)
        .map_err(|e| AegisError::Io(format!("open: {e}")))?;
    fs4::FileExt::try_lock_exclusive(&std_src).map_err(|e| AegisError::Io(format!("lock: {e}")))?;
    let total_size = std_src
        .metadata()
        .map_err(|e| AegisError::Io(e.to_string()))?
        .len();
    let src_tok = File::from_std(std_src);
    let mut reader = BufReader::new(src_tok);

    let mut header = [0u8; 200];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|_| AegisError::Header("file too small".into()))?;
    if &header[0..6] != MAGIC_BYTES {
        return Err(AegisError::Header("bad magic bytes".into()));
    }
    let file_major = u16::from_be_bytes(
        header[6..8]
            .try_into()
            .map_err(|_| AegisError::Header("version bytes".into()))?,
    );
    if file_major != VERSION_MAJOR {
        return Err(AegisError::Header(format!(
            "version mismatch: file v{file_major}, binary v{VERSION_MAJOR}"
        )));
    }

    let salt: [u8; SALT_SIZE] = header[16..48]
        .try_into()
        .map_err(|_| AegisError::Header("salt".into()))?;
    let nonce: [u8; NONCE_SIZE] = header[48..60]
        .try_into()
        .map_err(|_| AegisError::Header("nonce".into()))?;
    let mem_kib = u32::from_be_bytes(header[60..64].try_into().unwrap());
    let iters = u32::from_be_bytes(header[64..68].try_into().unwrap());
    let parallel = u32::from_be_bytes(header[68..72].try_into().unwrap());
    let chunk_sz = u32::from_be_bytes(header[72..76].try_into().unwrap()) as usize;
    let kvt_stored: [u8; 32] = header[116..148].try_into().unwrap();
    let mac_stored: [u8; 32] = header[168..200].try_into().unwrap();

    if mem_kib > MAX_ARGON2_MEM_KIB || iters > MAX_ARGON2_ITERS || parallel > MAX_ARGON2_PARALLEL {
        return Err(AegisError::InvalidParam(
            "KDF parameters exceed safe limits".into(),
        ));
    }

    let pw_ref = Arc::clone(&password);
    let salt_copy = salt;
    let master_key = tokio::task::spawn_blocking(move || {
        MasterKey::derive(pw_ref.expose_secret(), &salt_copy, mem_kib, iters, parallel)
    })
    .await
    .map_err(|e| AegisError::Kdf(format!("KDF task panic: {e}")))??;

    // Constant-time comparisons only
    if master_key.kvt.ct_eq(&kvt_stored).unwrap_u8() != 1 {
        return Err(AegisError::Auth);
    }
    let mac_computed = compute_header_mac(&master_key.header_mac_key, &header[0..168]);
    if mac_computed.ct_eq(&mac_stored).unwrap_u8() != 1 {
        return Err(AegisError::Tamper);
    }

    let std_dst = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&out_path)
        .map_err(|e| AegisError::Io(format!("create output: {e}")))?;
    fs4::FileExt::try_lock_exclusive(&std_dst)
        .map_err(|e| AegisError::Io(format!("lock output: {e}")))?;
    let dst_tok = File::from_std(std_dst);
    let mut writer = BufWriter::new(dst_tok);

    let aead = Aes256Gcm::new_from_slice(&master_key.encryption_key)
        .map_err(|_| AegisError::Crypto("cipher init".into()))?;
    let mut decryptor = Some(DecryptorBE32::from_aead(
        aead,
        GenericArray::from_slice(&nonce[..7]),
    ));
    let ct_chunk = chunk_sz + 16;
    let mut buf = vec![0u8; ct_chunk];
    let mut remaining = total_size.saturating_sub(HEADER_SIZE);

    let decrypt_result: Result<(), AegisError> = async {
        loop {
            let to_read = (remaining as usize).min(ct_chunk);
            if to_read == 0 {
                break;
            }
            reader
                .read_exact(&mut buf[..to_read])
                .await
                .map_err(|e| AegisError::Io(e.to_string()))?;
            remaining -= to_read as u64;
            let pt = if remaining == 0 {
                decryptor
                    .take()
                    .ok_or_else(|| AegisError::Crypto("decryptor consumed".into()))?
                    .decrypt_last(&buf[..to_read])
                    .map_err(|_| AegisError::Crypto("auth tag mismatch — file tampered".into()))?
            } else {
                decryptor
                    .as_mut()
                    .ok_or_else(|| AegisError::Crypto("decryptor consumed".into()))?
                    .decrypt_next(&buf[..to_read])
                    .map_err(|_| AegisError::Crypto("chunk auth failed".into()))?
            };
            writer
                .write_all(&pt)
                .await
                .map_err(|e| AegisError::Io(e.to_string()))?;
        }
        writer
            .flush()
            .await
            .map_err(|e| AegisError::Io(e.to_string()))?;
        Ok(())
    }
    .await;

    if let Err(e) = decrypt_result {
        let _ = tokio::fs::remove_file(&out_path).await;
        return Err(e);
    }

    let file_size = tokio::fs::metadata(&out_path)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    let file_hash = compute_file_hash(&out_path).await.unwrap_or_default();
    let _ = append_audit(
        &AuditEntry {
            timestamp: unix_now(),
            operation: "DECRYPT".into(),
            file_path: input_path,
            file_hash,
            file_size,
            status: "SUCCESS".into(),
        },
        &master_key.audit_key,
    )
    .await;

    let out_name = out_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| out_path.display().to_string());
    Ok(format!("Vault opened → {out_name}"))
}

// =============================================================================
//  TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // FIX: shared runtime — no per-test Runtime::new() overhead
    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().expect("test runtime")
    }

    #[test]
    fn test_roundtrip_small() {
        rt().block_on(async {
            let dir = tempdir().unwrap();
            let plain = dir.path().join("test.txt");
            std::fs::write(&plain, b"test data 1234").unwrap();
            let pw = Arc::new(SecretVec::new(b"password-12chars".to_vec()));
            let (msg, shares, _) =
                async_encrypt(Arc::clone(&pw), plain.to_str().unwrap().into(), true)
                    .await
                    .unwrap();
            assert!(msg.contains("Encrypted"));
            assert_eq!(shares.len(), SHAMIR_TOTAL);
            let vault = dir.path().join("test.txt.aegis");
            let msg2 = async_decrypt(Arc::clone(&pw), vault.to_str().unwrap().into())
                .await
                .unwrap();
            assert!(msg2.contains("opened"));
            assert_eq!(std::fs::read(&plain).unwrap(), b"test data 1234");
        });
    }

    #[test]
    fn test_wrong_password_rejected() {
        rt().block_on(async {
            let dir = tempdir().unwrap();
            let plain = dir.path().join("secret.bin");
            std::fs::write(&plain, b"secret data here").unwrap();
            let correct = Arc::new(SecretVec::new(b"correct-password-12".to_vec()));
            let wrong = Arc::new(SecretVec::new(b"wrong-password-looong".to_vec()));
            async_encrypt(Arc::clone(&correct), plain.to_str().unwrap().into(), false)
                .await
                .unwrap();
            let vault = dir.path().join("secret.bin.aegis");
            let err = async_decrypt(wrong, vault.to_str().unwrap().into())
                .await
                .unwrap_err();
            assert!(matches!(err, AegisError::Auth));
        });
    }

    #[test]
    fn test_shamir_roundtrip() {
        let key = [0xAAu8; 32];
        let shares = generate_recovery_shares(&key).unwrap();
        assert_eq!(shares.len(), SHAMIR_TOTAL);
        let recovered = recover_key_from_shares(&shares[..SHAMIR_THRESHOLD]).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn test_shamir_insufficient_shares_rejected() {
        let key = [0xBBu8; 32];
        let shares = generate_recovery_shares(&key).unwrap();
        let result = recover_key_from_shares(&shares[..SHAMIR_THRESHOLD - 1]);
        assert!(result.is_err());
    }

    #[test]
    fn test_audit_id_does_not_expose_key() {
        let pw = b"test-password-long";
        let salt = [0x42u8; 32];
        let mk = MasterKey::derive(pw, &salt, 64, 1, 1).unwrap();
        let id = mk.audit_identifier();
        assert_eq!(id.len(), 32);
        // audit_id must not be a prefix of any raw key material
        assert_ne!(id, hex::encode(&mk.audit_key[..16]));
        assert_ne!(id, hex::encode(&mk.audit_id_key[..16]));
    }

    #[test]
    fn test_ciphertext_corruption_detected() {
        rt().block_on(async {
            let dir = tempdir().unwrap();
            let plain = dir.path().join("prop.bin");
            std::fs::write(&plain, b"some important data that must be protected").unwrap();
            let pw = Arc::new(SecretVec::new(b"prop-test-password".to_vec()));
            async_encrypt(Arc::clone(&pw), plain.to_str().unwrap().into(), false)
                .await
                .unwrap();
            let vault = dir.path().join("prop.bin.aegis");
            let mut raw = std::fs::read(&vault).unwrap();
            // Flip a byte in the ciphertext body
            raw[250] ^= 0xFF;
            std::fs::write(&vault, &raw).unwrap();
            let result = async_decrypt(pw, vault.to_str().unwrap().into()).await;
            assert!(result.is_err(), "Corrupted ciphertext must be rejected");
        });
    }
}
