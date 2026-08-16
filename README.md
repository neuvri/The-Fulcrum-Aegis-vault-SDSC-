# THE FULCRUM — AEGIS Sovereign Vault v9.2

> نظام تخزين بارد مادي بأمان عسكري للاستخدام في تونس.  
> Physical cold-storage security system — air-gapped, military-grade encryption.

---

## الميزات الأمنية / Security Features

| Layer | Technology |
|-------|-----------|
| Key Derivation | Argon2id (128 MiB · 4 iters · 4 threads) |
| Encryption | AES-256-GCM streaming (512 KiB chunks) |
| Sub-keys | HKDF-SHA256 (7 independent keys) |
| Authentication | KVT + Header HMAC-SHA256 (constant-time) |
| Secret Sharing | Shamir 3-of-5 + QR codes |
| Audit Log | AES-256-GCM-SIV + HMAC-SHA256 (per-entry) |
| Nonce Safety | Persistent nonce registry — prevents reuse |
| Key Zeroize | `ZeroizeOnDrop` on all key material |
| Secure Delete | 7-pass DoD + random wipe before removal |
| LTO Tape | tar/mt on Linux, robocopy on Windows |
| Dashboard | Axum HTTPS + self-signed TLS (rcgen) |
| Biometrics | USB attendance with full audit trail |

---

## التشغيل / Running

```bash
# Full-featured CLI
cargo run --bin aegis-cli --release -- --help

# Interactive TUI
cargo run --bin aegis-vault --release

# Dashboard only
AEGIS_AUDIT_KEY=<64-hex-chars> AEGIS_DASHBOARD_PORT=8080 \
  cargo run --bin aegis-vault --release
```

### متغيرات البيئة / Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AEGIS_AUDIT_KEY` | for audit/dashboard cmds | 32 bytes hex-encoded (64 chars) |
| `AEGIS_AUDIT_PATH` | no | Audit log path (default: `aegis_audit.enc`) |
| `AEGIS_NONCE_PATH` | no | Nonce registry path (default: `aegis_nonces.log`) |
| `AEGIS_DASHBOARD_PORT` | no | Auto-start dashboard on this port |
| `AEGIS_LOG` | no | Tracing level (default: `warn`) |
| `AEGIS_DEV_MODE` | **never in prod** | `1` bypasses biometrics — DEV ONLY |

---

## هيكل الملفات / File Layout

```
src/
  main.rs        — TUI entry point + AEGIS_DEV_MODE startup guard
  cli.rs         — Full CLI (clap) — encrypt/decrypt/verify/lto/log/report/dashboard
  crypto.rs      — AES-256-GCM streaming, Argon2id, HKDF, Shamir, Nonce Registry
  audit.rs       — Encrypted audit log (AES-256-GCM-SIV + HMAC)
  biometrics.rs  — USB biometric attendance with audit trail
  dashboard.rs   — Axum HTTPS dashboard + TLS (rcgen)
  lto.rs         — LTO tape write/read (tar/mt on Linux, robocopy on Windows)
scripts/
  check.sh       — CI: fmt · clippy · build · unit tests · integration tests · audit
tests/
  integration_test.rs — 15 end-to-end pipeline tests
```

---

## الاختبارات / Tests

```bash
# Unit tests (crypto, audit, biometrics)
cargo test --lib

# Integration tests (full encrypt → decrypt → verify pipeline)
cargo test --test integration_test

# All tests
cargo test

# Full CI check (fmt + clippy + build + tests + audit + secret scan)
bash scripts/check.sh
```

### Integration test coverage

| # | Test |
|---|------|
| 1 | Full roundtrip — content + SHA-256 hash integrity |
| 2 | Shred: original deleted, vault survives |
| 3 | Wrong password → `Auth` error + partial output cleaned up |
| 4 | Tampered ciphertext → `Crypto/Tamper` error |
| 5 | Large file (1 MiB) roundtrip |
| 6 | Empty file roundtrip |
| 7 | Encrypt missing file → `Io` error |
| 8 | Decrypt missing vault → `Io` error |
| 9 | Shamir threshold recovery (exactly 3-of-5) |
| 10 | Shamir below threshold → error |
| 11 | Shamir non-consecutive subset (shares 1, 3, 5) |
| 12 | Different passwords → different ciphertext |
| 13 | Audit ID: deterministic for same key |
| 14 | Audit ID: unique per password |
| 15 | Same plaintext + same password → different ciphertext (random nonce) |

---

## تنبيهات الأمان / Security Notes

- **كلمة المرور** تُقرأ عبر `rpassword` فقط — لا من متغيرات البيئة ولا من الـ args.
- **AEGIS_DEV_MODE=1** يعطّل التحقق البيومتري ويُطلق تحذيراً أحمر عند بدء التشغيل.  
  **يجب عدم استخدامه في الإنتاج أبداً.**
- **nonce registry** يمنع إعادة استخدام أي nonce — يُخزَّن على القرص ويُحمَّل عند الإقلاع.
- **header MAC** يُقارَن بـ constant-time (`subtle::ct_eq`) — لا مجال لـ timing attacks.
- **audit log** مُشفَّر بـ AES-256-GCM-SIV مع HMAC لكل سجل — التلاعب يُكشَف فوراً.

---

## التغييرات في v9.2

- ✅ حُذف `src/cli (copy).rs` — ملف مزدوج.
- ✅ حُذف `crypto_final.txt` — مسودة قديمة تحتوي على مقارنة MAC غير ثابتة الوقت (`!=`).
- ✅ أُضيف startup guard في `main.rs`: تحذير أحمر فوري إذا كان `AEGIS_DEV_MODE=1`.
- ✅ أُضيفت 15 integration test شاملة في `tests/integration_test.rs`.
- ✅ تحسين `scripts/check.sh`: خطوة integration tests + فحص startup guard + فحص ملفات مزدوجة.

---

## الترخيص / License

Proprietary — Internal use only. The Fulcrum, Tunisia.
