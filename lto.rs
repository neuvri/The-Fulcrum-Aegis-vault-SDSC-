// =============================================================================
//  AEGIS SOVEREIGN VAULT — v9.1  |  LTO TAPE INTERFACE
//  Cross-platform: Linux / macOS / Windows
//
//  يدعم الكتابة/القراءة من أشرطة LTO عبر أوامر النظام (mt / tar).
//  على Windows يستخدم NTBackup/robocopy كبديل.
// =============================================================================

use crate::crypto::*;
use secrecy::SecretVec;
use std::path::Path;
use std::sync::Arc;

pub struct LtoTape {
    device: String,
}

impl LtoTape {
    /// device: مسار الجهاز مثل /dev/nst0 (Linux) أو \\.\Tape0 (Windows)
    pub fn new(device: &str) -> Self {
        Self {
            device: device.to_string(),
        }
    }

    /// كتابة ملف مشفر على شريط LTO
    pub async fn write_encrypted(
        &self,
        input_path: &str,
        password: Arc<SecretVec<u8>>,
    ) -> Result<String, AegisError> {
        let in_path = std::path::PathBuf::from(input_path);
        if !in_path.exists() {
            return Err(AegisError::Io(format!("الملف غير موجود: {}", input_path)));
        }

        // تشفير الملف أولاً إلى .aegis
        let (msg, _shares, audit_id) =
            async_encrypt(password, input_path.to_string(), false).await?;
        let aegis_str = format!("{input_path}.aegis");

        // كتابة الملف المشفر على الشريط
        self.tape_write(&aegis_str).await?;

        tracing::info!(
            device    = %self.device,
            file      = %input_path,
            audit_id  = %audit_id,
            "LTO write completed"
        );

        Ok(format!(
            "✅ {} → شريط LTO [{}] | AuditID: {}",
            msg, self.device, audit_id
        ))
    }

    /// قراءة ملف مشفر من شريط LTO وفك تشفيره
    pub async fn read_encrypted(
        &self,
        output_path: &str,
        password: Arc<SecretVec<u8>>,
    ) -> Result<String, AegisError> {
        // قراءة الملف من الشريط كـ .aegis مؤقت
        let temp_aegis = format!("{}.aegis", output_path);
        self.tape_read(&temp_aegis).await?;

        // فك التشفير
        let msg = async_decrypt(password, temp_aegis.clone()).await?;

        // حذف الملف المؤقت .aegis بعد فك التشفير
        if Path::new(&temp_aegis).exists() {
            tokio::fs::remove_file(&temp_aegis)
                .await
                .map_err(|e| AegisError::Io(format!("حذف الملف المؤقت: {}", e)))?;
        }

        tracing::info!(
            device = %self.device,
            output = %output_path,
            "LTO read completed"
        );

        Ok(format!("✅ {} من شريط LTO [{}]", msg, self.device))
    }

    // ── تطبيقات أوامر الشريط ──────────────────────────────────────────────

    async fn tape_write(&self, file_path: &str) -> Result<(), AegisError> {
        #[cfg(target_os = "windows")]
        {
            self.windows_tape_write(file_path).await
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.unix_tape_write(file_path).await
        }
    }

    async fn tape_read(&self, output_path: &str) -> Result<(), AegisError> {
        #[cfg(target_os = "windows")]
        {
            self.windows_tape_read(output_path).await
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.unix_tape_read(output_path).await
        }
    }

    // ── Unix / Linux / macOS ───────────────────────────────────────────────

    #[cfg(not(target_os = "windows"))]
    async fn unix_tape_write(&self, file_path: &str) -> Result<(), AegisError> {
        // الترجيع إلى نهاية البيانات أولاً (MTEOM)
        let mt_status = tokio::process::Command::new("mt")
            .args(["-f", &self.device, "eom"])
            .status()
            .await
            .map_err(|e| AegisError::Io(format!("mt eom: {e}")))?;

        if !mt_status.success() {
            tracing::warn!(device = %self.device, "mt eom failed — continuing anyway");
        }

        // كتابة الملف بـ tar
        let status = tokio::process::Command::new("tar")
            .args(["-cf", &self.device, file_path])
            .status()
            .await
            .map_err(|e| AegisError::Io(format!("tar write: {e}")))?;

        if !status.success() {
            return Err(AegisError::Io(format!(
                "فشل كتابة الشريط على '{}' — تأكد من اتصال الجهاز وصلاحيات الوصول",
                self.device
            )));
        }

        // علامة نهاية الملف
        let _ = tokio::process::Command::new("mt")
            .args(["-f", &self.device, "weof"])
            .status()
            .await;

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    async fn unix_tape_read(&self, output_path: &str) -> Result<(), AegisError> {
        // استخراج الملف من الشريط
        let out_dir = Path::new(output_path)
            .parent()
            .map(|p| p.to_str().unwrap_or("."))
            .unwrap_or(".");

        let status = tokio::process::Command::new("tar")
            .args(["-xf", &self.device, "-C", out_dir])
            .status()
            .await
            .map_err(|e| AegisError::Io(format!("tar read: {e}")))?;

        if !status.success() {
            return Err(AegisError::Io(format!(
                "فشل قراءة الشريط من '{}' — تأكد من اتصال الجهاز وتحديد موضع الشريط",
                self.device
            )));
        }

        Ok(())
    }

    // ── Windows ────────────────────────────────────────────────────────────

    #[cfg(target_os = "windows")]
    async fn windows_tape_write(&self, file_path: &str) -> Result<(), AegisError> {
        // على Windows: نستخدم robocopy أو ntbackup كبديل
        // هذا مثال يستخدم robocopy لنسخ الملف إلى الجهاز
        let status = tokio::process::Command::new("robocopy")
            .args([
                Path::new(file_path)
                    .parent()
                    .unwrap_or(Path::new("."))
                    .to_str()
                    .unwrap_or("."),
                &self.device,
                Path::new(file_path)
                    .file_name()
                    .unwrap_or_default()
                    .to_str()
                    .unwrap_or(""),
            ])
            .status()
            .await
            .map_err(|e| AegisError::Io(format!("robocopy write: {e}")))?;

        // robocopy تعيد 1 عند النجاح
        if status.code().unwrap_or(0) > 7 {
            return Err(AegisError::Io(format!(
                "فشل النسخ على '{}' — كود: {:?}",
                self.device,
                status.code()
            )));
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn windows_tape_read(&self, output_path: &str) -> Result<(), AegisError> {
        let out_dir = Path::new(output_path)
            .parent()
            .map(|p| p.to_str().unwrap_or("."))
            .unwrap_or(".");

        let status = tokio::process::Command::new("robocopy")
            .args([&self.device, out_dir, "*"])
            .status()
            .await
            .map_err(|e| AegisError::Io(format!("robocopy read: {e}")))?;

        if status.code().unwrap_or(0) > 7 {
            return Err(AegisError::Io(format!(
                "فشل القراءة من '{}' — كود: {:?}",
                self.device,
                status.code()
            )));
        }

        Ok(())
    }
}

// =============================================================================
//  TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lto_new() {
        let tape = LtoTape::new("/dev/nst0");
        assert_eq!(tape.device, "/dev/nst0");
    }

    #[test]
    fn test_lto_windows_device() {
        let tape = LtoTape::new(r"\\.\Tape0");
        assert_eq!(tape.device, r"\\.\Tape0");
    }
}
