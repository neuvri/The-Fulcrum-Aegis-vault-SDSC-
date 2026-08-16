// =============================================================================
//  AEGIS SOVEREIGN VAULT — v9.1  |  CLI INTERFACE
//  Cross-platform: Linux / macOS / Windows
//
//  Security fixes applied:
//    — get_audit_key_from_env() from lib (no duplication)
//    — --password flag REMOVED (would appear in ps/shell history)
//    — Passwords read via rpassword only (no env/args exposure)
//    — Zero audit key rejected explicitly (from shared lib)
// =============================================================================

use aegis_vault::audit::*;
use aegis_vault::biometrics::BiometricsManager;
use aegis_vault::crypto::*;
use aegis_vault::dashboard::run_dashboard_with_key;
use aegis_vault::get_audit_key_from_env;
use aegis_vault::lto::LtoTape;
use aegis_vault::sync::sync_audit_to_portal;
use clap::{Parser, Subcommand};
use secrecy::SecretVec;
use std::sync::Arc;

// =============================================================================
//  CLI DEFINITION
// =============================================================================

#[derive(Parser)]
#[command(name = "aegis-cli")]
#[command(about = "Aegis Sovereign Vault — CLI for The Fulcrum")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file (password prompted interactively)
    Encrypt {
        input: String,
        #[arg(
            long,
            default_value_t = false,
            help = "Secure-erase original after encryption (7 passes)"
        )]
        shred: bool,
    },
    /// Decrypt a vault file (password prompted interactively)
    Decrypt { input: String },
    /// Verify vault file integrity (header + magic bytes only)
    Verify { input: String },
    /// Write an encrypted file to an LTO tape
    LtoWrite { input: String, device: String },
    /// Read and decrypt a file from an LTO tape
    LtoRead { output: String, device: String },
    /// Log a physical media operation to the audit trail
    Log {
        media_id: String,
        client_id: String,
        operation: String,
        operator: String,
        location: String,
    },
    /// Generate a client audit report for a date range
    Report {
        client_id: String,
        /// Unix timestamp (seconds)
        start: u64,
        /// Unix timestamp (seconds)
        end: u64,
    },
    /// Run the internal web dashboard
    Dashboard {
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },
    /// Record biometric attendance for a user
    Attendance {
        user_id: String,
        /// in | out | vault-in | vault-out
        action: String,
    },
    /// Push new local audit entries to The Fulcrum client portal
    /// (requires AEGIS_PORTAL_URL and AEGIS_PORTAL_API_KEY)
    Sync,
}

// =============================================================================
//  MAIN
// =============================================================================

#[tokio::main]
async fn main() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(std::env::var("AEGIS_LOG").unwrap_or_else(|_| "warn".to_string()))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, shred } => {
            let pw = prompt_password("🔑 Master password: ").await;
            let pw_arc = Arc::new(SecretVec::new(pw.into_bytes()));
            match async_encrypt(pw_arc, input, shred).await {
                Ok((msg, shares, audit_id)) => {
                    println!("✅ {}", msg);
                    if !shares.is_empty() {
                        println!(
                            "\n🔑 RECOVERY SHARES (any {}/{} are enough):",
                            SHAMIR_THRESHOLD, SHAMIR_TOTAL
                        );
                        for share in &shares {
                            println!("\n━━━ Share {} ━━━", share.index);
                            println!("{}", share.qr_code_ascii);
                            println!(
                                "Hex: {}…",
                                &share.share_hex[..64.min(share.share_hex.len())]
                            );
                        }
                        println!("\n⚠️  Store each share in a separate, secure location.");
                        println!("🔑 Audit session ID: {}", audit_id);
                    }
                    Ok(())
                }
                Err(e) => Err(format!("❌ Encryption failed: {}", e)),
            }
        }

        Commands::Decrypt { input } => {
            let pw = prompt_password("🔑 Master password: ").await;
            let pw_arc = Arc::new(SecretVec::new(pw.into_bytes()));
            async_decrypt(pw_arc, input)
                .await
                .map(|msg| println!("✅ {}", msg))
                .map_err(|e| format!("❌ Decryption failed: {}", e))
        }

        Commands::Verify { input } => verify_integrity(&input),

        Commands::LtoWrite { input, device } => {
            let pw = prompt_password("🔑 Master password: ").await;
            let pw_arc = Arc::new(SecretVec::new(pw.into_bytes()));
            LtoTape::new(&device)
                .write_encrypted(&input, pw_arc)
                .await
                .map(|msg| println!("✅ {}", msg))
                .map_err(|e| format!("❌ LTO write failed: {}", e))
        }

        Commands::LtoRead { output, device } => {
            let pw = prompt_password("🔑 Master password: ").await;
            let pw_arc = Arc::new(SecretVec::new(pw.into_bytes()));
            LtoTape::new(&device)
                .read_encrypted(&output, pw_arc)
                .await
                .map(|msg| println!("✅ {}", msg))
                .map_err(|e| format!("❌ LTO read failed: {}", e))
        }

        Commands::Log {
            media_id,
            client_id,
            operation,
            operator,
            location,
        } => {
            let audit_key = match require_audit_key() {
                Ok(k) => k,
                Err(e) => return Err(e),
            };
            log_physical_operation_cmd(
                &media_id, &client_id, &operation, &operator, &location, &audit_key,
            )
            .await
        }

        Commands::Report {
            client_id,
            start,
            end,
        } => {
            let audit_key = match require_audit_key() {
                Ok(k) => k,
                Err(e) => return Err(e),
            };
            generate_client_report(&client_id, start, end, &audit_key)
                .await
                .map(|report| println!("{}", report))
                .map_err(|e| format!("❌ Report failed: {}", e))
        }

        Commands::Dashboard { port } => {
            let audit_key = match require_audit_key() {
                Ok(k) => k,
                Err(e) => return Err(e),
            };
            run_dashboard_with_key(port, audit_key)
                .await
                .map_err(|e| format!("❌ Dashboard: {}", e))
        }

        Commands::Attendance { user_id, action } => {
            let audit_key = match require_audit_key() {
                Ok(k) => k,
                Err(e) => return Err(e),
            };
            let action_enum = match parse_attendance_action(&action) {
                Ok(a) => a,
                Err(e) => return Err(e),
            };
            let device_path = if cfg!(windows) {
                "COM1"
            } else {
                "/dev/ttyUSB0"
            };
            BiometricsManager::new(device_path)
                .register_attendance(&user_id, action_enum, &audit_key)
                .await
                .map_err(|e| format!("❌ Attendance failed: {}", e))
        }

        Commands::Sync => {
            let audit_key = match require_audit_key() {
                Ok(k) => k,
                Err(e) => return Err(e),
            };
            match sync_audit_to_portal(&audit_key).await {
                Ok(0) => {
                    println!("✅ Portal sync: nothing new to push.");
                    Ok(())
                }
                Ok(n) => {
                    println!("✅ Portal sync: pushed {} audit event(s).", n);
                    Ok(())
                }
                Err(e) => Err(format!("❌ Portal sync failed: {}", e)),
            }
        }
    }
}

// =============================================================================
//  HELPERS
// =============================================================================

/// Require AEGIS_AUDIT_KEY — fail fast with a clear message if invalid.
fn require_audit_key() -> Result<[u8; 32], String> {
    get_audit_key_from_env().map_err(|e| format!("❌ {}", e))
}

/// Prompt for password without echoing — never read from env/args.
async fn prompt_password(prompt: &'static str) -> String {
    tokio::task::spawn_blocking(move || {
        rpassword::prompt_password(prompt).expect("Failed to read password from terminal")
    })
    .await
    .expect("Password input task panicked")
}

fn parse_attendance_action(action: &str) -> Result<AttendanceAction, String> {
    match action.to_lowercase().as_str() {
        "in" => Ok(AttendanceAction::ClockIn),
        "out" => Ok(AttendanceAction::ClockOut),
        "vault-in" => Ok(AttendanceAction::VaultEntry),
        "vault-out" => Ok(AttendanceAction::VaultExit),
        _ => Err(format!(
            "Unknown action '{}'. Valid options: in | out | vault-in | vault-out",
            action
        )),
    }
}

fn verify_integrity(path: &str) -> Result<(), String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("Cannot open '{}': {}", path, e))?;
    let size = file
        .metadata()
        .map_err(|e| format!("Metadata: {}", e))?
        .len();
    if size < HEADER_SIZE {
        return Err(format!(
            "File too small ({} bytes, minimum: {})",
            size, HEADER_SIZE
        ));
    }
    let mut reader = std::io::BufReader::new(file);
    let mut header = [0u8; 200];
    reader
        .read_exact(&mut header)
        .map_err(|e| format!("Read header: {}", e))?;
    if &header[0..6] != MAGIC_BYTES {
        return Err(format!(
            "Bad magic bytes: expected {:?}, found {:?}",
            MAGIC_BYTES,
            &header[0..6]
        ));
    }
    let file_major = u16::from_be_bytes(
        header[6..8]
            .try_into()
            .map_err(|_| "Corrupt header".to_string())?,
    );
    if file_major != VERSION_MAJOR {
        return Err(format!(
            "Version mismatch: file v{}, binary v{}",
            file_major, VERSION_MAJOR
        ));
    }
    println!("✅ Valid Aegis v{} vault — {} bytes", file_major, size);
    Ok(())
}

async fn log_physical_operation_cmd(
    media_id: &str,
    client_id: &str,
    operation: &str,
    operator: &str,
    location: &str,
    audit_key: &[u8; 32],
) -> Result<(), String> {
    let op = match operation.to_lowercase().as_str() {
        "receive" => PhysicalOperation::Receive,
        "store" => PhysicalOperation::Store,
        "retrieve" => PhysicalOperation::Retrieve,
        "ship" => PhysicalOperation::Ship,
        "destroy" => PhysicalOperation::Destroy,
        _ => {
            return Err(format!(
                "Unknown operation '{}'. Valid: receive | store | retrieve | ship | destroy",
                operation
            ))
        }
    };
    let entry = PhysicalAuditEntry {
        timestamp: unix_now(),
        operation: op,
        media_id: media_id.to_string(),
        client_id: client_id.to_string(),
        operator_id: operator.to_string(),
        location: location.to_string(),
        signature: String::new(),
    };
    log_physical_operation(entry, audit_key)
        .await
        .map_err(|e| e.to_string())?;
    println!("✅ Logged '{}' for media '{}'", operation, media_id);
    Ok(())
}
