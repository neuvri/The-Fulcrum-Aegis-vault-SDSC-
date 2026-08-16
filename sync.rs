// =============================================================================
//  AEGIS SOVEREIGN VAULT — PORTAL AUDIT SYNC
//
//  Pushes locally-recorded (and already-decrypted-in-memory-only) audit
//  entries to The Fulcrum client portal so operators can see vault activity
//  without direct access to the encrypted local audit trail.
//
//  Security notes:
//    - The on-disk audit log stays encrypted at rest; only decrypted,
//      in-memory entries are ever sent, and only over HTTPS/TLS.
//    - Auth is a per-client bearer-style API key issued by the portal
//      (X-Vault-Api-Key header) — never the vault's own audit/master keys.
//    - Sync state (last-synced timestamp) is stored locally so re-runs are
//      idempotent and never re-push already-acknowledged entries.
// =============================================================================

use crate::audit::read_audit_entries;
use crate::crypto::AegisError;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

static SYNC_STATE_PATH: Lazy<String> = Lazy::new(|| {
    std::env::var("AEGIS_SYNC_STATE_PATH").unwrap_or_else(|_| "aegis_sync_state.json".to_string())
});

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SyncState {
    last_synced_timestamp: u64,
}

#[derive(Debug, Serialize)]
struct VaultAuditEventPayload {
    operation: String,
    description: String,
    operator: Option<String>,
    #[serde(rename = "mediaId")]
    media_id: Option<String>,
    status: String,
    timestamp: u64,
}

#[derive(Debug, Serialize)]
struct IngestRequest {
    events: Vec<VaultAuditEventPayload>,
}

#[derive(Debug, Deserialize)]
struct IngestResponse {
    ingested: u64,
}

#[derive(Debug)]
pub struct SyncConfig {
    pub portal_url: String,
    pub api_key: String,
}

impl SyncConfig {
    pub fn from_env() -> Result<Self, String> {
        let portal_url = std::env::var("AEGIS_PORTAL_URL").map_err(|_| {
            "AEGIS_PORTAL_URL is not set (e.g. https://your-portal.example.com/api)".to_string()
        })?;
        let api_key = std::env::var("AEGIS_PORTAL_API_KEY")
            .map_err(|_| "AEGIS_PORTAL_API_KEY is not set".to_string())?;
        Ok(Self {
            portal_url: portal_url.trim_end_matches('/').to_string(),
            api_key,
        })
    }
}

async fn load_state() -> SyncState {
    match tokio::fs::read_to_string(SYNC_STATE_PATH.as_str()).await {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => SyncState::default(),
    }
}

async fn save_state(state: &SyncState) -> Result<(), AegisError> {
    let json = serde_json::to_string(state).map_err(|e| AegisError::Audit(e.to_string()))?;
    tokio::fs::write(SYNC_STATE_PATH.as_str(), json)
        .await
        .map_err(|e| AegisError::Io(format!("Cannot write sync state: {e}")))
}

fn extract_media_id(file_path: &str) -> Option<String> {
    file_path
        .strip_prefix("Media: ")
        .map(|s| s.trim().to_string())
}

/// Pushes any locally-recorded audit entries newer than the last successful
/// sync to the portal. Returns the number of entries pushed.
pub async fn sync_audit_to_portal(audit_key: &[u8; 32]) -> Result<usize, AegisError> {
    let config = SyncConfig::from_env().map_err(AegisError::Audit)?;
    let state = load_state().await;

    let entries = read_audit_entries(audit_key).await?;
    let mut pending: Vec<_> = entries
        .into_iter()
        .filter(|e| e.timestamp > state.last_synced_timestamp)
        .collect();
    // read_audit_entries returns newest-first; send in chronological order.
    pending.sort_by_key(|e| e.timestamp);

    if pending.is_empty() {
        return Ok(0);
    }

    let max_timestamp = pending
        .iter()
        .map(|e| e.timestamp)
        .max()
        .unwrap_or(state.last_synced_timestamp);

    let events: Vec<VaultAuditEventPayload> = pending
        .iter()
        .map(|e| VaultAuditEventPayload {
            operation: e.operation.clone(),
            description: e.file_path.clone(),
            operator: None,
            media_id: extract_media_id(&e.file_path),
            status: e.status.clone(),
            timestamp: e.timestamp,
        })
        .collect();

    let client = reqwest::Client::new();
    let url = format!("{}/vault/audit-events", config.portal_url);

    let response = client
        .post(&url)
        .header("X-Vault-Api-Key", &config.api_key)
        .json(&IngestRequest { events })
        .send()
        .await
        .map_err(|e| AegisError::Audit(format!("Portal sync request failed: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(AegisError::Audit(format!(
            "Portal rejected sync (status {status}): {body}"
        )));
    }

    let parsed: IngestResponse = response
        .json()
        .await
        .map_err(|e| AegisError::Audit(format!("Invalid portal response: {e}")))?;

    save_state(&SyncState {
        last_synced_timestamp: max_timestamp,
    })
    .await?;

    Ok(parsed.ingested as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_media_id_from_physical_path() {
        assert_eq!(
            extract_media_id("Media: TAPE-042"),
            Some("TAPE-042".to_string())
        );
    }

    #[test]
    fn returns_none_for_non_media_path() {
        assert_eq!(extract_media_id("/some/file.pdf"), None);
    }

    #[tokio::test]
    async fn state_roundtrips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync_state.json");
        std::env::set_var("AEGIS_SYNC_STATE_PATH", path.to_str().unwrap());

        let state = SyncState {
            last_synced_timestamp: 1_700_000_000,
        };
        save_state(&state).await.unwrap();
        let loaded = load_state().await;
        assert_eq!(loaded.last_synced_timestamp, 1_700_000_000);

        std::env::remove_var("AEGIS_SYNC_STATE_PATH");
    }

    #[tokio::test]
    async fn missing_config_env_errors_clearly() {
        std::env::remove_var("AEGIS_PORTAL_URL");
        std::env::remove_var("AEGIS_PORTAL_API_KEY");
        let err = SyncConfig::from_env().unwrap_err();
        assert!(err.contains("AEGIS_PORTAL_URL"));
    }
}
