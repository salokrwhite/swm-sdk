use crate::crypto::{base64url_encode, random_bytes, sha256, sha256_hex};
use crate::error::{Error, ErrorKind, Result};
use crate::platform::IdentityKey;
use crate::state::{IDENTITY_FILE, StateStore};
use std::fmt::Write as _;
use std::sync::Mutex;

pub(crate) struct DeviceIdentity {
    store: std::sync::Arc<StateStore>,
    key: Mutex<IdentityKey>,
    pub(crate) install_id: String,
    pub(crate) device_id: String,
    pub(crate) key_id: String,
    pub(crate) key_thumbprint: String,
    pub(crate) public_key_sec1: Vec<u8>,
}

impl DeviceIdentity {
    pub(crate) fn load_or_create(
        app_id: &str,
        store: std::sync::Arc<StateStore>,
    ) -> Result<std::sync::Arc<Self>> {
        if let Some((install_id, key_name)) = read_metadata(&store) {
            if let Ok(key) = IdentityKey::open(&key_name) {
                if let Ok(identity) = Self::from_key(store.clone(), install_id, key) {
                    return Ok(std::sync::Arc::new(identity));
                }
            }
            store.delete(IDENTITY_FILE);
        }
        let install_id = hex::encode(random_bytes(16)?);
        let key_name = build_key_name(app_id, &install_id);
        let key = IdentityKey::create(&key_name)?;
        let identity = Self::from_key(store.clone(), install_id.clone(), key)?;
        if let Err(error) = write_metadata(&store, &identity.install_id, &key_name) {
            let _ = identity.key.lock().map(|key| key.delete());
            return Err(error);
        }
        Ok(std::sync::Arc::new(identity))
    }

    pub(crate) fn create_pending(app_id: &str, store: std::sync::Arc<StateStore>) -> Result<Self> {
        let install_id = hex::encode(random_bytes(16)?);
        let key_name = build_key_name(app_id, &install_id);
        let key = IdentityKey::create(&key_name)?;
        match Self::from_key(store, install_id, key) {
            Ok(value) => Ok(value),
            Err(error) => Err(error),
        }
    }

    fn from_key(
        store: std::sync::Arc<StateStore>,
        install_id: String,
        key: IdentityKey,
    ) -> Result<Self> {
        let public_key_sec1 = match key.public_key_sec1() {
            Ok(value) => value,
            Err(error) => {
                let _ = key.close();
                return Err(error);
            }
        };
        if public_key_sec1.len() != 65 || public_key_sec1[0] != 4 {
            return Err(Error::new(
                ErrorKind::Identity,
                "CNG key did not return a P-256 SEC1 public key",
            ));
        }
        let key_thumbprint = base64url_encode(&sha256(&public_key_sec1));
        let device_id = sha256_hex(
            format!(
                "device_credential_v2\napp_id:{}\ninstall_id:{}\nkey_thumbprint:{}",
                store.app_id, install_id, key_thumbprint
            )
            .as_bytes(),
        );
        let key_id = format!("swm-device-{}", &key_thumbprint[..22]);
        Ok(Self {
            store,
            key: Mutex::new(key),
            install_id,
            device_id,
            key_id,
            key_thumbprint,
            public_key_sec1,
        })
    }

    pub(crate) fn sign_digest(&self, digest: &[u8]) -> Result<[u8; 64]> {
        self.key
            .lock()
            .map_err(|_| Error::new(ErrorKind::Identity, "device key lock poisoned"))?
            .sign_digest(digest)
    }

    pub(crate) fn commit_pending(&self) -> Result<()> {
        let key_name = self
            .key
            .lock()
            .map_err(|_| Error::new(ErrorKind::Identity, "device key lock poisoned"))?
            .name()
            .to_string();
        write_metadata(&self.store, &self.install_id, &key_name)
    }

    #[allow(dead_code)]
    pub(crate) fn delete_pending(&self) {
        if let Ok(key) = self.key.lock() {
            let _ = key.delete();
        }
    }

    pub(crate) fn close(&self) {
        if let Ok(key) = self.key.lock() {
            let _ = key.close();
        }
    }
}

fn read_metadata(store: &StateStore) -> Option<(String, String)> {
    let plaintext = store.read_protected(IDENTITY_FILE)?;
    let text = String::from_utf8(plaintext).ok()?;
    let mut parts = text.split('\n');
    if parts.next()? != "v2" {
        return None;
    }
    let install_id = parts.next()?.to_string();
    let key_name = parts.next()?.trim().to_string();
    if install_id.len() != 32 || key_name.is_empty() {
        return None;
    }
    Some((install_id, key_name))
}

fn write_metadata(store: &StateStore, install_id: &str, key_name: &str) -> Result<()> {
    store.write_protected(
        IDENTITY_FILE,
        format!("v2\n{install_id}\n{key_name}\n").as_bytes(),
    )
}

pub(crate) fn build_key_name(app_id: &str, install_id: &str) -> String {
    let mut hash = String::new();
    let digest = sha256_hex(app_id.as_bytes());
    write!(&mut hash, "SwmSdk.{}.{}", &digest[..12], install_id).unwrap();
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn cross_language_identity_compatibility() {
        if std::env::var("SWM_TEST_CROSS_LANGUAGE").ok().as_deref() != Some("1") {
            return;
        }
        let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../Go/testdata/crosslang/SwmCrossLanguageHelper.csproj");

        let app_id = "00000000-0000-0000-0000-000000000901";
        let directory = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(StateStore::new(app_id, Some(directory.path())).unwrap());
        let identity = DeviceIdentity::load_or_create(app_id, store).unwrap();
        let helper_output = run_helper(&helper, app_id, directory.path());
        assert_eq!(helper_output["device_id"], identity.device_id);
        assert_eq!(helper_output["install_id"], identity.install_id);
        assert_eq!(helper_output["key_id"], identity.key_id);
        assert_eq!(helper_output["key_thumbprint"], identity.key_thumbprint);
        identity.delete_pending();

        let app_id = "00000000-0000-0000-0000-000000000902";
        let directory = tempfile::tempdir().unwrap();
        let helper_output = run_helper(&helper, app_id, directory.path());
        let store = std::sync::Arc::new(StateStore::new(app_id, Some(directory.path())).unwrap());
        let identity = DeviceIdentity::load_or_create(app_id, store).unwrap();
        assert_eq!(helper_output["device_id"], identity.device_id);
        assert_eq!(helper_output["install_id"], identity.install_id);
        assert_eq!(helper_output["key_id"], identity.key_id);
        assert_eq!(helper_output["key_thumbprint"], identity.key_thumbprint);
        identity.delete_pending();
    }

    fn run_helper(
        project: &std::path::Path,
        app_id: &str,
        directory: &std::path::Path,
    ) -> std::collections::HashMap<String, String> {
        let output = Command::new("dotnet")
            .args([
                "run",
                "--project",
                project.to_str().unwrap(),
                "-c",
                "Release",
                "--",
                app_id,
                directory.to_str().unwrap(),
            ])
            .output()
            .expect("dotnet is required for cross-language tests");
        assert!(
            output.status.success(),
            "helper failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
            .collect()
    }
}
