// =============================================================================
//  AEGIS SOVEREIGN VAULT — v9.1  |  BIOMETRICS INTEGRATION
//  Cross-platform: Linux / macOS / Windows
//
//  Security fixes applied:
//    ✅ Hardware failure returns Err in production — NO silent bypass
//    ✅ Dev bypass ONLY when AEGIS_DEV_MODE=1 is explicitly set
//    ✅ Every bypass logs a loud warning to stderr and tracing
// =============================================================================

use crate::audit::*;
use crate::crypto::*;

pub struct BiometricsManager {
    device_path: String,
}

pub struct AttendanceRecord {
    pub user_id: String,
    pub user_name: String,
    pub timestamp: u64,
    pub action: AttendanceAction,
}

impl BiometricsManager {
    pub fn new(device_path: &str) -> Self {
        Self {
            device_path: device_path.to_string(),
        }
    }

    pub async fn register_attendance(
        &self,
        user_id: &str,
        action: AttendanceAction,
        audit_key: &[u8; 32],
    ) -> Result<(), AegisError> {
        let timestamp = unix_now();

        let verified = self.verify_user(user_id).await?;
        if !verified {
            return Err(AegisError::Biometrics(format!(
                "Biometric verification failed for user '{}'",
                user_id
            )));
        }

        let action_str = match &action {
            AttendanceAction::ClockIn => "CLOCK_IN",
            AttendanceAction::ClockOut => "CLOCK_OUT",
            AttendanceAction::VaultEntry => "VAULT_ENTRY",
            AttendanceAction::VaultExit => "VAULT_EXIT",
        };

        let record = AttendanceRecord {
            user_id: user_id.to_string(),
            user_name: user_id.to_string(),
            timestamp,
            action,
        };

        append_audit(
            &AuditEntry {
                timestamp: record.timestamp,
                operation: format!("ATTENDANCE_{}", action_str),
                file_path: format!("User: {}", record.user_id),
                file_hash: String::new(),
                file_size: 0,
                status: "SUCCESS".to_string(),
            },
            audit_key,
        )
        .await?;

        tracing::info!(user_id = %record.user_id, action = %action_str, "Attendance recorded");
        Ok(())
    }

    pub async fn verify_user(&self, user_id: &str) -> Result<bool, AegisError> {
        match self.try_hardware_verify(user_id) {
            Ok(result) => Ok(result),
            Err(hw_err) => {
                let dev_mode = std::env::var("AEGIS_DEV_MODE")
                    .map(|v| v.trim() == "1")
                    .unwrap_or(false);

                if dev_mode {
                    tracing::warn!(
                        target  = "aegis::security",
                        device  = %self.device_path,
                        error   = %hw_err,
                        user_id = %user_id,
                        "⚠️  AEGIS_DEV_MODE=1 — biometric bypass active. DISABLE IN PRODUCTION."
                    );
                    eprintln!(
                        "⚠️  [SECURITY WARNING] AEGIS_DEV_MODE=1 bypass for '{}'. NOT FOR PRODUCTION.",
                        user_id
                    );
                    Ok(true)
                } else {
                    Err(AegisError::Biometrics(format!(
                        "Biometric device '{}' unavailable: {}.\n  \
                         For development only: export AEGIS_DEV_MODE=1",
                        self.device_path, hw_err
                    )))
                }
            }
        }
    }

    fn try_hardware_verify(&self, _user_id: &str) -> Result<bool, String> {
        Err(format!("No device connected at '{}'", self.device_path))
    }

    pub async fn enroll_user(&self, user_id: &str, user_name: &str) -> Result<(), AegisError> {
        tracing::info!(user_id = %user_id, user_name = %user_name, "Enrolling biometric user");
        Ok(())
    }
}

// =============================================================================
//  TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn production_rejects_missing_hardware() {
        std::env::remove_var("AEGIS_DEV_MODE");
        let bio = BiometricsManager::new("/dev/nonexistent");
        let result = bio.verify_user("user1").await;
        assert!(
            matches!(result, Err(AegisError::Biometrics(_))),
            "Missing hardware must return Err in production"
        );
    }

    #[tokio::test]
    async fn dev_mode_bypass_allowed() {
        std::env::set_var("AEGIS_DEV_MODE", "1");
        let bio = BiometricsManager::new("/dev/nonexistent");
        let result = bio.verify_user("dev-user").await;
        assert!(result.unwrap(), "DEV_MODE=1 should bypass hardware check");
        std::env::remove_var("AEGIS_DEV_MODE");
    }

    #[tokio::test]
    async fn dev_mode_off_by_default() {
        std::env::remove_var("AEGIS_DEV_MODE");
        let bio = BiometricsManager::new("/dev/nonexistent");
        assert!(bio.verify_user("user").await.is_err());
    }

    #[tokio::test]
    async fn dev_mode_zero_does_not_bypass() {
        std::env::set_var("AEGIS_DEV_MODE", "0");
        let bio = BiometricsManager::new("/dev/nonexistent");
        let result = bio.verify_user("user").await;
        assert!(result.is_err(), "AEGIS_DEV_MODE=0 must NOT bypass");
        std::env::remove_var("AEGIS_DEV_MODE");
    }

    #[tokio::test]
    async fn enroll_user_does_not_panic() {
        let bio = BiometricsManager::new("/dev/nonexistent");
        bio.enroll_user("user-x", "User X").await.unwrap();
    }
}
