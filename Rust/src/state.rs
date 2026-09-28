use crate::crypto::{sha256, sha256_hex};
use crate::error::Result;
use crate::platform;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const IDENTITY_FILE: &str = "identity.bin";
pub(crate) const OFFLINE_FILE: &str = "offline.bin";
pub(crate) const INTEGRITY_POLICY_FILE: &str = "integrity-policy.bin";

pub(crate) struct StateStore {
    pub(crate) directory: PathBuf,
    pub(crate) app_id: String,
    entropy: Vec<u8>,
}

impl StateStore {
    pub(crate) fn new(app_id: &str, override_directory: Option<&Path>) -> Result<Self> {
        let directory = match override_directory {
            Some(value) => value.to_path_buf(),
            None => default_storage_directory(app_id)?,
        };
        fs::create_dir_all(&directory)?;
        Ok(Self {
            directory,
            app_id: app_id.to_string(),
            entropy: sha256(format!("SwmSdkStateV2\n{app_id}").as_bytes()).to_vec(),
        })
    }

    pub(crate) fn path(&self, file_name: &str) -> PathBuf {
        self.directory.join(file_name)
    }

    pub(crate) fn read_protected(&self, file_name: &str) -> Option<Vec<u8>> {
        let ciphertext = fs::read(self.path(file_name)).ok()?;
        if ciphertext.is_empty() || ciphertext.len() > 1024 * 1024 {
            return None;
        }
        platform::unprotect(&ciphertext, &self.entropy).ok()
    }

    pub(crate) fn write_protected(&self, file_name: &str, plaintext: &[u8]) -> Result<()> {
        let ciphertext = platform::protect(plaintext, &self.entropy)?;
        let path = self.path(file_name);
        let temporary = path.with_extension(format!(
            "{}tmp",
            path.extension()
                .and_then(|value| value.to_str())
                .map(|value| format!("{value}."))
                .unwrap_or_default()
        ));
        fs::write(&temporary, ciphertext)?;
        platform::replace_file(&temporary, &path)?;
        Ok(())
    }

    pub(crate) fn delete(&self, file_name: &str) {
        let _ = fs::remove_file(self.path(file_name));
    }
}

fn default_storage_directory(app_id: &str) -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let hash = sha256_hex(app_id.as_bytes());
    Ok(local.join("SwmSdk").join(&hash[..12]))
}
