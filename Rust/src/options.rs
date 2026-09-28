use crate::error::{Error, ErrorKind, Result};
use crate::models::IntegrityEvidence;
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;

/// Callback invoked with `(downloaded_bytes, total_bytes)`.
pub type ProgressCallback = Arc<dyn Fn(u64, u64) + Send + Sync + 'static>;

#[derive(Clone, Debug, Default)]
pub struct CheckUpdateOptions {
    pub user_id: Option<String>,
    pub attributes: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Clone, Debug)]
pub struct IntegrityEvidenceRequest {
    pub app_id: String,
    pub release_id: String,
    pub version: String,
    pub version_code: Option<i32>,
    pub arch: String,
    pub package_root: PathBuf,
    pub manifest_path: String,
}

#[async_trait]
pub trait IntegrityEvidenceProvider: Send + Sync {
    async fn get_evidence(&self, request: IntegrityEvidenceRequest) -> Result<IntegrityEvidence>;
}

#[derive(Clone, Default)]
pub struct HostIntegrityOptions {
    pub enabled: bool,
    pub package_root: Option<PathBuf>,
    pub manifest_path: String,
    pub evidence_provider: Option<Arc<dyn IntegrityEvidenceProvider>>,
}

#[derive(Clone)]
pub struct ClientOptions {
    pub base_url: String,
    pub web_base_url: Option<String>,
    pub app_id: String,
    pub release_id: String,
    pub version: String,
    pub version_code: Option<i32>,
    pub root_trust_key_id: String,
    pub root_trust_public_key: String,
    pub channel: String,
    pub platform: String,
    pub arch: String,
    pub device_id: Option<String>,
    pub storage_directory: Option<PathBuf>,
    pub allow_insecure_http: bool,
    pub http_client: Option<reqwest::Client>,
    pub host_integrity: HostIntegrityOptions,
}

impl ClientOptions {
    pub fn builder() -> ClientOptionsBuilder {
        ClientOptionsBuilder::default()
    }
}

#[derive(Default)]
pub struct ClientOptionsBuilder {
    base_url: Option<String>,
    web_base_url: Option<String>,
    app_id: Option<String>,
    release_id: Option<String>,
    version: Option<String>,
    version_code: Option<i32>,
    root_trust_key_id: Option<String>,
    root_trust_public_key: Option<String>,
    channel: Option<String>,
    platform: Option<String>,
    arch: Option<String>,
    device_id: Option<String>,
    storage_directory: Option<PathBuf>,
    allow_insecure_http: bool,
    http_client: Option<reqwest::Client>,
    host_integrity: HostIntegrityOptions,
}

impl ClientOptionsBuilder {
    pub fn base_url(mut self, value: impl Into<String>) -> Self {
        self.base_url = Some(value.into());
        self
    }
    pub fn web_base_url(mut self, value: impl Into<String>) -> Self {
        self.web_base_url = Some(value.into());
        self
    }
    pub fn app_id(mut self, value: impl Into<String>) -> Self {
        self.app_id = Some(value.into());
        self
    }
    pub fn release_id(mut self, value: impl Into<String>) -> Self {
        self.release_id = Some(value.into());
        self
    }
    pub fn version(mut self, value: impl Into<String>) -> Self {
        self.version = Some(value.into());
        self
    }
    pub fn version_code(mut self, value: i32) -> Self {
        self.version_code = Some(value);
        self
    }
    pub fn root_trust_key_id(mut self, value: impl Into<String>) -> Self {
        self.root_trust_key_id = Some(value.into());
        self
    }
    pub fn root_trust_public_key(mut self, value: impl Into<String>) -> Self {
        self.root_trust_public_key = Some(value.into());
        self
    }
    pub fn channel(mut self, value: impl Into<String>) -> Self {
        self.channel = Some(value.into());
        self
    }
    pub fn platform(mut self, value: impl Into<String>) -> Self {
        self.platform = Some(value.into());
        self
    }
    pub fn arch(mut self, value: impl Into<String>) -> Self {
        self.arch = Some(value.into());
        self
    }
    pub fn device_id(mut self, value: impl Into<String>) -> Self {
        self.device_id = Some(value.into());
        self
    }
    pub fn storage_directory(mut self, value: PathBuf) -> Self {
        self.storage_directory = Some(value);
        self
    }
    pub fn allow_insecure_http(mut self, value: bool) -> Self {
        self.allow_insecure_http = value;
        self
    }
    pub fn http_client(mut self, value: reqwest::Client) -> Self {
        self.http_client = Some(value);
        self
    }
    pub fn host_integrity(mut self, value: HostIntegrityOptions) -> Self {
        self.host_integrity = value;
        self
    }
    pub fn build(self) -> Result<ClientOptions> {
        let mut options = ClientOptions {
            base_url: self.base_url.unwrap_or_default(),
            web_base_url: self.web_base_url,
            app_id: self.app_id.unwrap_or_default(),
            release_id: self.release_id.unwrap_or_default(),
            version: self.version.unwrap_or_default(),
            version_code: self.version_code,
            root_trust_key_id: self.root_trust_key_id.unwrap_or_default(),
            root_trust_public_key: self.root_trust_public_key.unwrap_or_default(),
            channel: self.channel.unwrap_or_else(|| "stable".into()),
            platform: self.platform.unwrap_or_else(|| "windows".into()),
            arch: self.arch.unwrap_or_else(default_arch),
            device_id: self.device_id,
            storage_directory: self.storage_directory,
            allow_insecure_http: self.allow_insecure_http,
            http_client: self.http_client,
            host_integrity: self.host_integrity,
        };
        options.host_integrity.manifest_path = if options.host_integrity.manifest_path.is_empty() {
            "release-integrity.v2".into()
        } else {
            options.host_integrity.manifest_path.clone()
        };
        validate_options(&options)?;
        Ok(options)
    }
}

pub(crate) fn validate_options(options: &ClientOptions) -> Result<()> {
    if options.app_id.is_empty()
        || options.release_id.is_empty()
        || options.version.is_empty()
        || options.root_trust_key_id.is_empty()
        || options.root_trust_public_key.is_empty()
    {
        return Err(Error::new(
            ErrorKind::Configuration,
            "base URL, app ID, release ID, version, and root trust material are required",
        ));
    }
    if !is_uuid(&options.app_id) || !is_uuid(&options.release_id) {
        return Err(Error::new(
            ErrorKind::Configuration,
            "app_id and release_id must be UUID values",
        ));
    }
    let base = url::Url::parse(&options.base_url)?;
    if base.scheme() != "https" && !(options.allow_insecure_http && base.scheme() == "http") {
        return Err(Error::new(
            ErrorKind::Configuration,
            "base_url must be an absolute HTTPS URL",
        ));
    }
    if options.platform != "windows" {
        return Err(Error::new(
            ErrorKind::Configuration,
            "platform must be windows",
        ));
    }
    if options.arch != "x86" && options.arch != "x64" {
        return Err(Error::new(
            ErrorKind::Configuration,
            "arch must be x86 or x64",
        ));
    }
    if crate::crypto::decode_key_material(&options.root_trust_public_key)?.len() != 32 {
        return Err(Error::new(
            ErrorKind::Configuration,
            "root trust public key must be 32 bytes",
        ));
    }
    if options.host_integrity.manifest_path.is_empty()
        || options.host_integrity.manifest_path.starts_with('/')
        || options.host_integrity.manifest_path.contains(':')
    {
        return Err(Error::new(
            ErrorKind::Configuration,
            "host integrity manifest path must be package-relative",
        ));
    }
    Ok(())
}

fn default_arch() -> String {
    if cfg!(target_arch = "x86") {
        "x86".into()
    } else {
        "x64".into()
    }
}

pub(crate) fn is_uuid(value: &str) -> bool {
    if value.len() != 36
        || value.as_bytes().get(8) != Some(&b'-')
        || value.as_bytes().get(13) != Some(&b'-')
        || value.as_bytes().get(18) != Some(&b'-')
        || value.as_bytes().get(23) != Some(&b'-')
    {
        return false;
    }
    value.chars().enumerate().all(|(index, character)| {
        matches!(index, 8 | 13 | 18 | 23) || character.is_ascii_hexdigit()
    })
}
