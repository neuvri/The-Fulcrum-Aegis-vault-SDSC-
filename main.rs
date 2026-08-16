// =============================================================================
//  AEGIS SOVEREIGN VAULT — v9.2  |  MAIN ENTRY POINT
//  Cross-platform: Linux / macOS / Windows
//
//  Improvements in v9.2:
//    — AEGIS_DEV_MODE=1 triggers loud startup banner + tracing error
//    — Passwords read interactively only (never from env/args)
//    — get_audit_key_from_env() used from lib (no duplication)
// =============================================================================

use aegis_vault::crypto::*;
use aegis_vault::dashboard::run_dashboard_with_key;
use aegis_vault::get_audit_key_from_env;
use secrecy::SecretVec;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(std::env::var("AEGIS_LOG").unwrap_or_else(|_| "warn".to_string()))
        .init();

    // ── Production safety guard ──────────────────────────────────────────────
    // Warn loudly at startup so DEV_MODE is never silently left on in production.
    if std::env::var("AEGIS_DEV_MODE")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
    {
        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════╗");
        eprintln!("║  ⚠️  SECURITY WARNING: AEGIS_DEV_MODE=1 IS ACTIVE    ║");
        eprintln!("║  Biometric verification is BYPASSED.                 ║");
        eprintln!("║  THIS CONFIGURATION MUST NOT BE USED IN PRODUCTION.  ║");
        eprintln!("║  Run:  unset AEGIS_DEV_MODE  before any deployment.  ║");
        eprintln!("╚══════════════════════════════════════════════════════╝");
        eprintln!();
        tracing::error!(
            target = "aegis::security",
            "AEGIS_DEV_MODE=1 active at startup — biometric bypass ENABLED. DISABLE IN PRODUCTION."
        );
    }

    println!("╔══════════════════════════════════════════════════╗");
    println!("║        THE FULCRUM — AEGIS Sovereign Vault        ║");
    println!(
        "║              v{}  |  Internal Use Only             ║",
        env!("CARGO_PKG_VERSION")
    );
    println!("╚══════════════════════════════════════════════════╝");
    println!();

    // Dashboard auto-mode when AEGIS_DASHBOARD_PORT is set
    if let Ok(port_str) = std::env::var("AEGIS_DASHBOARD_PORT") {
        let port: u16 = port_str.parse().unwrap_or(8080);
        let audit_key = match get_audit_key_from_env() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("❌ {}", e);
                std::process::exit(1);
            }
        };
        if let Err(e) = run_dashboard_with_key(port, audit_key).await {
            eprintln!("❌ Dashboard: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // Interactive TUI
    println!("Available commands:");
    println!("  1) Encrypt file");
    println!("  2) Decrypt vault");
    println!("  3) Run dashboard");
    println!("  q) Quit");
    println!();
    println!("Tip: use `aegis-cli --help` for the full CLI.");
    println!();

    loop {
        print!("aegis> ");
        use std::io::Write;
        std::io::stdout().flush().ok();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap_or(0);
        let choice = input.trim();

        match choice {
            "1" => {
                print!("File path: ");
                std::io::stdout().flush().ok();
                let mut path = String::new();
                std::io::stdin().read_line(&mut path).unwrap_or(0);
                let path = path.trim().to_string();

                let password =
                    rpassword::prompt_password("🔑 Master password: ").unwrap_or_default();
                let pw_arc = Arc::new(SecretVec::new(password.into_bytes()));

                match async_encrypt(pw_arc, path, false).await {
                    Ok((msg, shares, audit_id)) => {
                        println!("✅ {}", msg);
                        println!("🔑 Audit ID: {}", audit_id);
                        if !shares.is_empty() {
                            println!(
                                "\n⚠️  Save recovery shares ({}/{}) in separate secure locations:",
                                SHAMIR_THRESHOLD, SHAMIR_TOTAL
                            );
                            for s in &shares {
                                println!("  Share {}: {}…", s.index, &s.share_hex[..32]);
                            }
                        }
                    }
                    Err(e) => eprintln!("❌ {}", e),
                }
            }

            "2" => {
                print!("Vault path (.aegis): ");
                std::io::stdout().flush().ok();
                let mut path = String::new();
                std::io::stdin().read_line(&mut path).unwrap_or(0);
                let path = path.trim().to_string();

                let password =
                    rpassword::prompt_password("🔑 Master password: ").unwrap_or_default();
                let pw_arc = Arc::new(SecretVec::new(password.into_bytes()));

                match async_decrypt(pw_arc, path).await {
                    Ok(msg) => println!("✅ {}", msg),
                    Err(e) => eprintln!("❌ {}", e),
                }
            }

            "3" => {
                let port: u16 = std::env::var("AEGIS_DASHBOARD_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(8080);
                let audit_key = match get_audit_key_from_env() {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        continue;
                    }
                };
                println!("📊 Starting dashboard on port {}…", port);
                if let Err(e) = run_dashboard_with_key(port, audit_key).await {
                    eprintln!("❌ {}", e);
                }
            }

            "q" | "quit" | "exit" => {
                println!("Goodbye.");
                break;
            }

            "" => continue,
            _ => println!("Unknown command. Choose from the menu or type q to quit."),
        }
        println!();
    }
}
