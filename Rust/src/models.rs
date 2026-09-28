use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use time::OffsetDateTime;

/// Current authorization session state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudState {
    Unavailable,
    Authorizing,
    Available,
    Expired,
    Revoked,
    IntegrityFailure,
    TimeSyncFailure,
    OfflineLocked,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct MaintenanceInfo {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default)]
    pub active: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateInfo {
    #[serde(default)]
    pub update_available: bool,
    #[serde(default)]
    pub mandatory: bool,
    #[serde(default)]
    pub heartbeat_interval_seconds: i32,
    #[serde(default)]
    pub open_in_browser: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_trust_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_trust_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_arch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authz_protocol: Option<String>,
    #[serde(default)]
    pub host_integrity_required: bool,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub rollback_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintenance: Option<MaintenanceInfo>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HeartbeatResult {
    #[serde(default)]
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintenance: Option<MaintenanceInfo>,
}

#[derive(Clone, Debug, Default)]
pub struct FeedbackRequest {
    pub content: String,
    pub rating: Option<i32>,
    pub contact: Option<String>,
    pub app_version: Option<String>,
    pub attachment_paths: Vec<PathBuf>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FeedbackResult {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub id: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EnrollmentTicket {
    #[serde(default)]
    pub ticket: String,
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default)]
    pub audience: String,
}

#[derive(Clone, Debug, Default)]
pub struct DeviceKeyRotationResult {
    pub registration_id: String,
    pub install_id: String,
    pub key_id: String,
    pub device_id: String,
}

#[derive(Clone, Debug, Default)]
pub struct OperationAuthorizationRequest {
    pub operation: String,
    pub plan: Vec<u8>,
    pub step_count: u32,
    pub total_bytes: u64,
    pub consumer_module: String,
    pub consumer_challenge: Option<Vec<u8>>,
    pub host_executable_path: Option<PathBuf>,
    pub consumer_module_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OperationGrant {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub app_id: String,
    #[serde(default)]
    pub release_id: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub device_key_id: String,
    #[serde(default)]
    pub key_thumbprint: String,
    #[serde(default)]
    pub device_public_key: String,
    #[serde(default)]
    pub authz_public_key: String,
    #[serde(default)]
    pub authz_key_id: String,
    #[serde(default)]
    pub authz_root_trust_key_id: String,
    #[serde(default)]
    pub authz_root_trust_signature: String,
    #[serde(default)]
    pub session: String,
    #[serde(default)]
    pub grant_id: String,
    #[serde(default)]
    pub operation: String,
    #[serde(default)]
    pub plan_sha256: String,
    #[serde(default)]
    pub step_count: u32,
    #[serde(default)]
    pub total_bytes: u64,
    #[serde(default)]
    pub issued_at: i64,
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default)]
    pub consumer_challenge: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_exe_sha256: Option<String>,
    #[serde(default)]
    pub consumer_module: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer_module_sha256: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OperationConsumptionReceipt {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub grant_id: String,
    #[serde(default)]
    pub operation: String,
    #[serde(default)]
    pub plan_sha256: String,
    #[serde(default)]
    pub step_count: u32,
    #[serde(default)]
    pub total_bytes: u64,
    #[serde(default)]
    pub consumer_challenge: String,
    #[serde(default)]
    pub consumed_at: i64,
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_exe_sha256: Option<String>,
    #[serde(default)]
    pub consumer_module: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer_module_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub event_name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub event_time: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, serde_json::Value>>,
}

impl Default for Event {
    fn default() -> Self {
        Self {
            device_id: None,
            event_name: String::new(),
            event_time: OffsetDateTime::now_utc(),
            channel_code: None,
            properties: None,
            attributes: None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateEvent {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub event_type: String,
    #[serde(default)]
    pub org_id: String,
    #[serde(default)]
    pub app_id: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub channel_code: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub release_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintenance_start_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct UpdateStreamOptions {
    pub current_version: Option<String>,
    pub version_code: Option<i32>,
    pub reconnect: bool,
    pub reconnect_backoff: std::time::Duration,
    pub reconnect_max_backoff: std::time::Duration,
    pub jitter: bool,
}

impl Default for UpdateStreamOptions {
    fn default() -> Self {
        Self {
            current_version: None,
            version_code: None,
            reconnect: true,
            reconnect_backoff: std::time::Duration::from_millis(1500),
            reconnect_max_backoff: std::time::Duration::from_secs(20),
            jitter: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DebugRequestTicket {
    pub request_id: String,
    pub watch_token: String,
    pub expires_at: i64,
    pub(crate) credentials: DebugCredentials,
    pub(crate) session_id: String,
}

#[derive(Clone, Debug, Default)]
pub struct DebugDecisionEvent {
    pub state: String,
    pub reason: Option<String>,
    pub authorization_expires_at: i64,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DebugCredentials {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IntegrityEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_failure_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_evidence_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_files: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct HardwareEvidence {
    pub version: u32,
    pub component_mask: u32,
    pub aggregate_hash: String,
}
