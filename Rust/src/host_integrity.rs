use crate::error::{Error, ErrorKind, Result};
use crate::models::IntegrityEvidence;
use crate::options::{ClientOptions, IntegrityEvidenceRequest};
use crate::rim2;
use crate::state::{INTEGRITY_POLICY_FILE, StateStore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;

pub(crate) struct HostIntegrityManager {
    options: ClientOptions,
    store: Arc<StateStore>,
    manifest: Mutex<Option<(PathBuf, rim2::Rim2Manifest)>>,
}

impl HostIntegrityManager {
    pub(crate) fn new(options: ClientOptions, store: Arc<StateStore>) -> Self {
        Self {
            options,
            store,
            manifest: Mutex::new(None),
        }
    }

    pub(crate) fn read_cached_policy(&self) -> Option<bool> {
        let plaintext = self.store.read_protected(INTEGRITY_POLICY_FILE)?;
        let text = String::from_utf8(plaintext).ok()?;
        let parts: Vec<_> = text.split('\n').collect();
        if parts.len() < 5
            || parts[0] != "SwmSdkIntegrityPolicyV1"
            || parts[2] != self.options.app_id
            || parts[3] != self.options.release_id
            || parts[4] != version_code_string(self.options.version_code)
        {
            return None;
        }
        match parts[1] {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        }
    }

    pub(crate) fn store_policy(&self, required: bool) {
        if self.read_cached_policy() == Some(required) {
            return;
        }
        let text = [
            "SwmSdkIntegrityPolicyV1",
            if required { "1" } else { "0" },
            &self.options.app_id,
            &self.options.release_id,
            &version_code_string(self.options.version_code),
            &time::OffsetDateTime::now_utc().unix_timestamp().to_string(),
        ]
        .join("\n")
            + "\n";
        let _ = self
            .store
            .write_protected(INTEGRITY_POLICY_FILE, text.as_bytes());
    }

    pub(crate) async fn get_evidence(&self) -> Result<IntegrityEvidence> {
        if let Some(provider) = &self.options.host_integrity.evidence_provider {
            let root = self.package_root()?;
            return provider
                .get_evidence(IntegrityEvidenceRequest {
                    app_id: self.options.app_id.clone(),
                    release_id: self.options.release_id.clone(),
                    version: self.options.version.clone(),
                    version_code: self.options.version_code,
                    arch: self.options.arch.clone(),
                    package_root: root,
                    manifest_path: self.options.host_integrity.manifest_path.clone(),
                })
                .await;
        }
        if !self.options.host_integrity.enabled {
            return Ok(IntegrityEvidence::default());
        }
        let manifest = match self.load_manifest().await {
            Ok(value) => value,
            Err(error) => {
                return Ok(IntegrityEvidence {
                    integrity_state: Some("failed".into()),
                    integrity_failure_code: Some(
                        error
                            .code
                            .unwrap_or_else(|| "host_integrity_internal_error".into()),
                    ),
                    ..Default::default()
                });
            }
        };
        let root = self.package_root()?;
        let mut files = HashMap::new();
        for file in &manifest.files {
            let path = resolve_package_path(&root, &file.path)?;
            match hash_file(&path).await {
                Ok(hash) => {
                    files.insert(file.path.to_ascii_lowercase(), hex::encode(hash));
                }
                Err(error) if error.kind == ErrorKind::Validation => continue,
                Err(_) => {
                    return Ok(IntegrityEvidence {
                        integrity_state: Some("failed".into()),
                        integrity_failure_code: Some("host_file_io_failed".into()),
                        ..Default::default()
                    });
                }
            }
        }
        Ok(IntegrityEvidence {
            integrity_state: Some("verified".into()),
            integrity_evidence_version: Some(2),
            integrity_manifest_sha256: Some(manifest.manifest_sha256),
            integrity_files: Some(files),
            ..Default::default()
        })
    }

    pub(crate) async fn get_required_evidence(&self) -> Result<IntegrityEvidence> {
        let evidence = self.get_evidence().await?;
        if evidence.integrity_state.as_deref() == Some("failed") {
            return Err(Error::new(
                ErrorKind::Integrity,
                evidence
                    .integrity_failure_code
                    .clone()
                    .unwrap_or_else(|| "host_integrity_internal_error".into()),
            ));
        }
        Ok(evidence)
    }

    pub(crate) async fn resolve_operation_hashes(
        &self,
        host_path: &Path,
        module_path: &Path,
    ) -> Result<(String, String)> {
        let host = hash_file(host_path).await?;
        let module = hash_file(module_path).await?;
        Ok((hex::encode(host), hex::encode(module)))
    }

    pub(crate) async fn load_manifest(&self) -> Result<rim2::Rim2Manifest> {
        let root = self.package_root()?;
        if let Some((cached_root, manifest)) = self
            .manifest
            .lock()
            .map_err(|_| Error::new(ErrorKind::Integrity, "manifest lock poisoned"))?
            .as_ref()
        {
            if cached_root == &root {
                return Ok(manifest.clone());
            }
        }
        let path = resolve_package_path(&root, &self.options.host_integrity.manifest_path)?;
        let raw = tokio::fs::read(&path).await?;
        let manifest = rim2::parse_and_verify(
            &raw,
            &self.options.app_id,
            &self.options.release_id,
            &self.options.version,
            self.options.version_code,
            &self.options.arch,
            &self.options.root_trust_key_id,
            &self.options.root_trust_public_key,
        )?;
        *self
            .manifest
            .lock()
            .map_err(|_| Error::new(ErrorKind::Integrity, "manifest lock poisoned"))? =
            Some((root, manifest.clone()));
        Ok(manifest)
    }

    fn package_root(&self) -> Result<PathBuf> {
        if let Some(root) = &self.options.host_integrity.package_root {
            return Ok(root.clone());
        }
        let executable = std::env::current_exe()?;
        executable
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| Error::new(ErrorKind::Integrity, "executable path has no parent"))
    }
}

fn resolve_package_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let normalized = relative.replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.contains(':')
        || normalized
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::new(ErrorKind::Integrity, "integrity path is unsafe"));
    }
    let path = root.join(normalized);
    if !path.starts_with(root) {
        return Err(Error::new(
            ErrorKind::Integrity,
            "integrity path escapes package root",
        ));
    }
    Ok(path)
}

async fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| Error::new(ErrorKind::Validation, error.to_string()).with_source(error))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 128 * 1024];
    loop {
        let count = file.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

fn version_code_string(value: Option<i32>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}
