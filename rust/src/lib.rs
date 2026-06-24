use reqwest::blocking::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use base64::Engine;
use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::time::Duration;
use std::thread::sleep;
use std::thread;

type HmacSha256 = Hmac<Sha256>;

pub const API_ERROR_CODE_AUTHZ_INVALID: &str = "authz_invalid";
pub const API_ERROR_CODE_AUTHZ_DENIED: &str = "authz_denied";

#[derive(Debug)]
pub struct FeedbackDisabledError;

impl std::fmt::Display for FeedbackDisabledError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "feedback disabled")
    }
}

impl std::error::Error for FeedbackDisabledError {}

/// Raised when a required authorization verdict is missing or invalid (fail closed).
#[derive(Debug)]
pub struct AuthzError {
    pub code: String,
    pub message: String,
}

impl AuthzError {
    fn new(code: &str, message: &str) -> Self {
        Self { code: code.to_string(), message: message.to_string() }
    }
}

impl std::fmt::Display for AuthzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AuthzError {}

fn is_feedback_disabled_body(body: &str) -> bool {
    if body.trim().is_empty() {
        return false;
    }
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(err) = value.get("error") {
            if let Some(code) = err.get("code").and_then(|c| c.as_str()) {
                return code.eq_ignore_ascii_case("feedback_disabled");
            }
            if let Some(code) = err.as_str() {
                return code.eq_ignore_ascii_case("feedback_disabled");
            }
        }
    }
    false
}

#[derive(Default)]
pub struct Client {
    base_url: String,
    app_id: String,
    app_secret: String,
    pub channel: String,
    pub platform: String,
    pub arch: String,
    pub device_id: String,
    pub attributes: serde_json::Value,
    pub retries: u32,
    pub backoff_ms: u64,
    pub signature_verifier: Option<fn(&str, &str) -> bool>,
    /// When true, every call that can carry a signed verdict fails closed unless the
    /// response has a valid Ed25519 "allow" bound to this request + device.
    pub require_authz: bool,
    /// key_id -> Ed25519 public key (hex or base64).
    pub authz_public_keys: HashMap<String, String>,
    pub authz_clock_skew_seconds: i64,
    http: HttpClient,
}

#[derive(Serialize)]
struct UpdateCheckRequest<'a> {
    channel_code: &'a str,
    current_version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_code: Option<i32>,
    platform: &'a str,
    arch: &'a str,
    device_id: &'a str,
    attributes: &'a serde_json::Value,
}

pub const CONTROL_EVENT_SHUTDOWN: &str = "device_shutdown";
pub const CONTROL_EVENT_MAINTENANCE_SCHEDULED: &str = "maintenance_scheduled";
pub const CONTROL_EVENT_MAINTENANCE_CANCELLED: &str = "maintenance_cancelled";

#[derive(Deserialize, Debug, Clone)]
pub struct Maintenance {
    pub enabled: bool,
    #[serde(default)]
    pub start_at: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    pub active: bool,
}

/// Device-bound authorization verdict signed by the server with an Ed25519 key.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct AuthzEnvelope {
    #[serde(default)]
    pub decision: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub issued_at: i64,
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub signature: String,
}

#[derive(Deserialize, Debug)]
pub struct UpdateCheckResponse {
    pub update_available: bool,
    pub mandatory: bool,
    pub heartbeat_interval_seconds: Option<i64>,
    pub release_id: Option<String>,
    pub version: Option<String>,
    pub notes: Option<String>,
    pub download_url: Option<String>,
    pub checksum_sha256: Option<String>,
    pub signature: Option<String>,
    pub size: Option<i64>,
    pub rollback_allowed: Option<bool>,
    pub release_notes_url: Option<String>,
    #[serde(default)]
    pub maintenance: Option<Maintenance>,
    #[serde(default)]
    pub authz: Option<AuthzEnvelope>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct UpdatePushEvent {
    pub id: Option<String>,
    pub event_type: String,
    pub org_id: String,
    pub app_id: String,
    pub channel_code: String,
    pub platform: String,
    pub arch: String,
    pub release_id: String,
    pub published_at: String,
    pub reason: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub maintenance_start_at: Option<String>,
}

#[derive(Clone)]
pub struct UpdateStreamOptions {
    pub channel_code: Option<String>,
    pub platform: Option<String>,
    pub arch: Option<String>,
    pub device_id: Option<String>,
    pub current_version: Option<String>,
    pub version_code: Option<i32>,
    pub reconnect: bool,
    pub reconnect_backoff_ms: u64,
    pub reconnect_max_backoff_ms: u64,
    pub jitter: bool,
}

impl Default for UpdateStreamOptions {
    fn default() -> Self {
        Self {
            channel_code: None,
            platform: None,
            arch: None,
            device_id: None,
            current_version: None,
            version_code: None,
            reconnect: true,
            reconnect_backoff_ms: 1500,
            reconnect_max_backoff_ms: 20000,
            jitter: true,
        }
    }
}

pub struct UpdateWatchHandle {
    stop: Arc<AtomicBool>,
}

impl UpdateWatchHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[derive(Serialize)]
struct Event<'a> {
    device_id: &'a str,
    event_name: &'a str,
    event_time: String,
    channel_code: &'a str,
    properties: serde_json::Value,
    attributes: &'a serde_json::Value,
}

// --- request signing (HMAC) -------------------------------------------------

// RFC3986 escape matching the backend (Go url.QueryEscape + '+'->'%20', '*'->'%2A').
fn escape_rfc3986(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

// Canonical query: pairs sorted by key then value, RFC3986-escaped, joined '&'.
fn canonical_query(pairs: &[(String, String)]) -> String {
    let mut items = pairs.to_vec();
    items.sort();
    items
        .iter()
        .map(|(k, v)| format!("{}={}", escape_rfc3986(k), escape_rfc3986(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn sha256_hex(body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(body);
    hex::encode(h.finalize())
}

fn hmac_hex(secret: &str, canonical: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(canonical.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

// Builds the signed client request headers and returns (headers, nonce).
fn build_signed_headers(
    app_id: &str,
    app_secret: &str,
    method: &str,
    pathname: &str,
    canonical_q: &str,
    body: &[u8],
) -> (Vec<(&'static str, String)>, String) {
    let ts = chrono::Utc::now().timestamp().to_string();
    let nonce = uuid::Uuid::new_v4().to_string();
    let canonical = [
        method.to_uppercase(),
        pathname.to_string(),
        canonical_q.to_string(),
        sha256_hex(body),
        ts.clone(),
        nonce.clone(),
        app_id.to_string(),
    ]
    .join("\n");
    let sig = hmac_hex(app_secret, &canonical);
    let headers = vec![
        ("X-App-Id", app_id.to_string()),
        ("X-Timestamp", ts),
        ("X-Nonce", nonce.clone()),
        ("X-Signature", sig),
        ("X-Sign-Version", "v1".to_string()),
    ];
    (headers, nonce)
}

// --- authz verification -----------------------------------------------------

fn decode_key_material(value: &str) -> Result<Vec<u8>, ()> {
    let v = value.trim();
    if v.is_empty() {
        return Err(());
    }
    if v.len() % 2 == 0 && v.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Ok(b) = hex::decode(v) {
            return Ok(b);
        }
    }
    base64::engine::general_purpose::STANDARD.decode(v).map_err(|_| ())
}

// Must match backend internal/auth/authz.go authzCanonical byte-for-byte.
fn authz_canonical(app_id: &str, env: &AuthzEnvelope) -> String {
    [
        "authz_v1".to_string(),
        format!("app_id:{}", app_id),
        format!("device_id:{}", env.device_id),
        format!("nonce:{}", env.nonce),
        format!("decision:{}", env.decision),
        format!("reason:{}", env.reason),
        format!("issued_at:{}", env.issued_at),
        format!("expires_at:{}", env.expires_at),
        format!("key_id:{}", env.key_id),
    ]
    .join("\n")
}

#[allow(clippy::too_many_arguments)]
fn verify_authz_impl(
    require_authz: bool,
    authz_public_keys: &HashMap<String, String>,
    skew_secs: i64,
    app_id: &str,
    device_id: &str,
    env: Option<&AuthzEnvelope>,
    request_nonce: &str,
) -> Result<(), AuthzError> {
    if !require_authz {
        return Ok(());
    }
    let env = match env {
        Some(e) => e,
        None => return Err(AuthzError::new(API_ERROR_CODE_AUTHZ_INVALID, "authorization missing")),
    };
    if request_nonce.is_empty() || env.nonce != request_nonce {
        return Err(AuthzError::new(API_ERROR_CODE_AUTHZ_INVALID, "authorization nonce mismatch"));
    }
    if env.device_id != device_id {
        return Err(AuthzError::new(API_ERROR_CODE_AUTHZ_INVALID, "authorization device mismatch"));
    }
    let skew = if skew_secs > 0 { skew_secs } else { 120 };
    let now = chrono::Utc::now().timestamp();
    if env.expires_at <= 0 || now > env.expires_at + skew {
        return Err(AuthzError::new(API_ERROR_CODE_AUTHZ_INVALID, "authorization expired"));
    }
    let pub_encoded = match authz_public_keys.get(&env.key_id) {
        Some(p) if !p.trim().is_empty() => p,
        _ => return Err(AuthzError::new(API_ERROR_CODE_AUTHZ_INVALID, &format!("authorization key unknown: {}", env.key_id))),
    };
    if env.signature.trim().is_empty() {
        return Err(AuthzError::new(API_ERROR_CODE_AUTHZ_INVALID, "authorization signature missing"));
    }
    let pub_bytes = decode_key_material(pub_encoded).map_err(|_| AuthzError::new(API_ERROR_CODE_AUTHZ_INVALID, "authorization public key invalid"))?;
    let pub_arr: [u8; 32] = pub_bytes.as_slice().try_into().map_err(|_| AuthzError::new(API_ERROR_CODE_AUTHZ_INVALID, "authorization public key invalid"))?;
    let vk = VerifyingKey::from_bytes(&pub_arr).map_err(|_| AuthzError::new(API_ERROR_CODE_AUTHZ_INVALID, "authorization public key invalid"))?;
    let sig_bytes = decode_key_material(&env.signature).map_err(|_| AuthzError::new(API_ERROR_CODE_AUTHZ_INVALID, "authorization signature invalid encoding"))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| AuthzError::new(API_ERROR_CODE_AUTHZ_INVALID, "authorization signature invalid"))?;
    let msg = authz_canonical(app_id, env);
    vk.verify(msg.as_bytes(), &sig).map_err(|_| AuthzError::new(API_ERROR_CODE_AUTHZ_INVALID, "authorization signature invalid"))?;
    if env.decision != "allow" {
        let reason = if env.reason.trim().is_empty() { "access denied" } else { env.reason.as_str() };
        return Err(AuthzError::new(API_ERROR_CODE_AUTHZ_DENIED, &format!("authorization denied: {}", reason)));
    }
    Ok(())
}

fn mp_field(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", name).as_bytes());
    body.extend_from_slice(value.as_bytes());
    body.extend_from_slice(b"\r\n");
}

fn mp_file(body: &mut Vec<u8>, boundary: &str, name: &str, filename: &str, content: &[u8]) {
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n", name, filename).as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(content);
    body.extend_from_slice(b"\r\n");
}

impl Client {
    pub fn new(base_url: &str, app_id: &str, app_secret: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            app_id: app_id.to_string(),
            app_secret: app_secret.to_string(),
            http: HttpClient::new(),
            attributes: serde_json::json!({}),
            retries: 2,
            backoff_ms: 500,
            signature_verifier: None,
            require_authz: false,
            authz_public_keys: HashMap::new(),
            authz_clock_skew_seconds: 120,
            ..Default::default()
        }
    }

    fn verify_authz(&self, env: Option<&AuthzEnvelope>, request_nonce: &str) -> Result<(), AuthzError> {
        verify_authz_impl(
            self.require_authz,
            &self.authz_public_keys,
            self.authz_clock_skew_seconds,
            &self.app_id,
            &self.device_id,
            env,
            request_nonce,
        )
    }

    fn verify_response_authz(&self, body: &str, request_nonce: &str) -> Result<(), AuthzError> {
        if !self.require_authz {
            return Ok(());
        }
        let env = serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("authz").cloned())
            .and_then(|a| serde_json::from_value::<AuthzEnvelope>(a).ok());
        self.verify_authz(env.as_ref(), request_nonce)
    }

    fn post_with_retry<T: Serialize>(&self, path: &str, payload: &T) -> Result<(reqwest::blocking::Response, String), reqwest::Error> {
        // Serialize once and sign the exact bytes we send (the server hashes the raw body).
        let body = serde_json::to_vec(payload).unwrap_or_default();
        let mut last_err = None;
        for attempt in 0..=self.retries {
            let (headers, nonce) = build_signed_headers(&self.app_id, &self.app_secret, "POST", path, "", &body);
            let mut req = self
                .http
                .post(format!("{}{}", self.base_url, path))
                .header("Content-Type", "application/json")
                .body(body.clone());
            for (k, v) in &headers {
                req = req.header(*k, v);
            }
            match req.send() {
                Ok(resp) => return Ok((resp, nonce)),
                Err(err) => {
                    last_err = Some(err);
                    let backoff = self.backoff_ms * (1u64 << attempt);
                    sleep(Duration::from_millis(backoff));
                }
            }
        }
        Err(last_err.unwrap())
    }

    pub fn check_update(&self, current_version: &str, version_code: Option<i32>) -> Result<UpdateCheckResponse, Box<dyn std::error::Error>> {
        let req = UpdateCheckRequest {
            channel_code: &self.channel,
            current_version,
            version_code,
            platform: &self.platform,
            arch: &self.arch,
            device_id: &self.device_id,
            attributes: &self.attributes,
        };

        let (resp, nonce) = self.post_with_retry("/api/client/update-check", &req)?;
        let resp = resp.error_for_status()?;
        let text = resp.text()?;
        let out: UpdateCheckResponse = serde_json::from_str(&text)?;
        // Fail closed: when require_authz, the response must carry a valid signed "allow".
        self.verify_authz(out.authz.as_ref(), &nonce)?;
        Ok(out)
    }

    pub fn start_update_stream<F, E>(&self, options: UpdateStreamOptions, on_event: F, on_error: Option<E>) -> Result<UpdateWatchHandle, Box<dyn std::error::Error>>
    where
        F: Fn(UpdatePushEvent) + Send + Sync + 'static,
        E: Fn(String) + Send + Sync + 'static,
    {
        let channel = options.channel_code.clone().unwrap_or_else(|| self.channel.clone());
        let platform = options.platform.clone().unwrap_or_else(|| self.platform.clone());
        let arch = options.arch.clone().unwrap_or_else(|| self.arch.clone());
        let device_id = options.device_id.clone().unwrap_or_else(|| self.device_id.clone());
        if channel.trim().is_empty() || platform.trim().is_empty() || arch.trim().is_empty() || device_id.trim().is_empty() {
            return Err("channel_code/platform/arch/device_id required".into());
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let client = self.http.clone();
        let base_url = self.base_url.clone();
        let app_id = self.app_id.clone();
        let app_secret = self.app_secret.clone();
        let require_authz = self.require_authz;
        let authz_public_keys = self.authz_public_keys.clone();
        let skew = self.authz_clock_skew_seconds;
        let on_event = Arc::new(on_event);
        let on_error = on_error.map(Arc::new);
        thread::spawn(move || {
            let mut backoff = options.reconnect_backoff_ms.max(300);
            let max_backoff = options.reconnect_max_backoff_ms.max(backoff);
            while !stop_clone.load(Ordering::Relaxed) {
                let mut params = vec![
                    ("device_id".to_string(), device_id.clone()),
                    ("channel_code".to_string(), channel.clone()),
                    ("platform".to_string(), platform.clone()),
                    ("arch".to_string(), arch.clone()),
                ];
                if let Some(v) = options.current_version.clone() {
                    params.push(("current_version".to_string(), v));
                }
                if let Some(v) = options.version_code {
                    params.push(("version_code".to_string(), v.to_string()));
                }
                let query = canonical_query(&params);
                let (headers, nonce) = build_signed_headers(&app_id, &app_secret, "GET", "/api/client/updates/stream", &query, &[]);
                let url = format!("{}/api/client/updates/stream?{}", base_url, query);
                let mut builder = client.get(url);
                for (k, v) in &headers {
                    builder = builder.header(*k, v);
                }
                match builder.send() {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        if status == 401 || status == 403 {
                            if let Some(cb) = &on_error {
                                cb(format!("stream unauthorized: {}", status));
                            }
                            return;
                        }
                        if status >= 300 {
                            if let Some(cb) = &on_error {
                                cb(format!("stream failed: {}", status));
                            }
                        } else {
                            backoff = options.reconnect_backoff_ms.max(300);
                            // When require_authz, ignore pushed events until a valid
                            // authz event proves the stream comes from the real server.
                            let mut authz_ok = !require_authz;
                            let mut event_type = String::new();
                            let mut data = String::new();
                            let reader = std::io::BufReader::new(resp);
                            let mut fatal = false;
                            for line in reader.lines() {
                                if stop_clone.load(Ordering::Relaxed) {
                                    return;
                                }
                                let line = match line {
                                    Ok(l) => l,
                                    Err(_) => break,
                                };
                                let clean = line.trim();
                                if clean.is_empty() {
                                    if !data.is_empty() {
                                        if event_type == "authz" {
                                            if require_authz {
                                                match serde_json::from_str::<AuthzEnvelope>(&data) {
                                                    Ok(env) => {
                                                        if let Err(e) = verify_authz_impl(require_authz, &authz_public_keys, skew, &app_id, &device_id, Some(&env), &nonce) {
                                                            if let Some(cb) = &on_error {
                                                                cb(e.to_string());
                                                            }
                                                            fatal = true;
                                                            break;
                                                        }
                                                        authz_ok = true;
                                                    }
                                                    Err(_) => {
                                                        if let Some(cb) = &on_error {
                                                            cb("authorization malformed".to_string());
                                                        }
                                                        fatal = true;
                                                        break;
                                                    }
                                                }
                                            }
                                        } else if event_type != "connected" && authz_ok {
                                            if let Ok(evt) = serde_json::from_str::<UpdatePushEvent>(&data) {
                                                on_event(evt);
                                            }
                                        }
                                    }
                                    event_type.clear();
                                    data.clear();
                                    continue;
                                }
                                if clean.starts_with(':') {
                                    continue;
                                }
                                if let Some(v) = clean.strip_prefix("event:") {
                                    event_type = v.trim().to_string();
                                } else if let Some(v) = clean.strip_prefix("data:") {
                                    if !data.is_empty() {
                                        data.push('\n');
                                    }
                                    data.push_str(v.trim());
                                }
                            }
                            // A failed/denied verdict means the server is fake or the
                            // device is revoked — stop, don't reconnect.
                            if fatal {
                                return;
                            }
                        }
                    }
                    Err(err) => {
                        if let Some(cb) = &on_error {
                            cb(err.to_string());
                        }
                    }
                }
                if !options.reconnect {
                    return;
                }
                let mut wait = backoff;
                if options.jitter {
                    wait += wait / 2;
                }
                sleep(Duration::from_millis(wait));
                backoff = (backoff * 2).min(max_backoff);
            }
        });

        Ok(UpdateWatchHandle { stop })
    }

    pub fn report_event(&self, event_name: &str, properties: serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
        let event = Event {
            device_id: &self.device_id,
            event_name,
            event_time: chrono::Utc::now().to_rfc3339(),
            channel_code: &self.channel,
            properties,
            attributes: &self.attributes,
        };

        let (resp, nonce) = self.post_with_retry("/api/client/events", &event)?;
        let resp = resp.error_for_status()?;
        let text = resp.text()?;
        self.verify_response_authz(&text, &nonce)?;
        Ok(())
    }

    pub fn report_heartbeat(&self, app_version: Option<&str>, user_id: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
        let mut map = serde_json::Map::new();
        map.insert("device_id".to_string(), serde_json::Value::String(self.device_id.clone()));
        if !self.channel.is_empty() {
            map.insert("channel_code".to_string(), serde_json::Value::String(self.channel.clone()));
        }
        if !self.platform.is_empty() {
            map.insert("platform".to_string(), serde_json::Value::String(self.platform.clone()));
        }
        if !self.arch.is_empty() {
            map.insert("arch".to_string(), serde_json::Value::String(self.arch.clone()));
        }
        if let Some(v) = app_version {
            if !v.is_empty() {
                map.insert("app_version".to_string(), serde_json::Value::String(v.to_string()));
            }
        }
        if let Some(v) = user_id {
            if !v.is_empty() {
                map.insert("user_id".to_string(), serde_json::Value::String(v.to_string()));
            }
        }
        if !self.attributes.is_null() && !self.attributes.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            map.insert("attributes".to_string(), self.attributes.clone());
        }
        let payload = serde_json::Value::Object(map);
        let (resp, nonce) = self.post_with_retry("/api/client/heartbeat", &payload)?;
        let resp = resp.error_for_status()?;
        let text = resp.text()?;
        self.verify_response_authz(&text, &nonce)?;
        Ok(())
    }

    pub fn report_events(&self, events: serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
        let payload = serde_json::json!({ "events": events });
        let (resp, nonce) = self.post_with_retry("/api/client/events", &payload)?;
        let resp = resp.error_for_status()?;
        let text = resp.text()?;
        self.verify_response_authz(&text, &nonce)?;
        Ok(())
    }

    pub fn report_feedback(
        &self,
        content: &str,
        rating: Option<i32>,
        contact: Option<&str>,
        attachments: Vec<&Path>,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if content.trim().is_empty() {
            return Err("content required".into());
        }

        // Build the multipart body manually so we can sign the exact bytes sent.
        let boundary = format!("----swm-{}", uuid::Uuid::new_v4());
        let mut body: Vec<u8> = Vec::new();
        mp_field(&mut body, &boundary, "device_id", &self.device_id);
        mp_field(&mut body, &boundary, "content", content);
        if !self.channel.is_empty() {
            mp_field(&mut body, &boundary, "channel_code", &self.channel);
        }
        if let Some(score) = rating {
            mp_field(&mut body, &boundary, "rating", &score.to_string());
        }
        if let Some(value) = contact {
            if !value.trim().is_empty() {
                mp_field(&mut body, &boundary, "contact", value);
            }
        }

        let mut merged = serde_json::Map::new();
        if let Some(meta) = metadata {
            if let Some(obj) = meta.as_object() {
                for (k, v) in obj {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }
        if !self.attributes.is_null() && !self.attributes.as_object().map(|m| m.is_empty()).unwrap_or(true) && !merged.contains_key("attributes") {
            merged.insert("attributes".to_string(), self.attributes.clone());
        }
        if !merged.is_empty() {
            let metadata_value = serde_json::Value::Object(merged);
            mp_field(&mut body, &boundary, "metadata", &metadata_value.to_string());
            if let Some(app_version) = metadata_value.get("app_version") {
                mp_field(&mut body, &boundary, "app_version", app_version.to_string().trim_matches('"'));
            }
        }

        for path in attachments {
            if !path.exists() {
                continue;
            }
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("attachment");
            let mut content_bytes = Vec::new();
            File::open(path)?.read_to_end(&mut content_bytes)?;
            mp_file(&mut body, &boundary, "attachments", file_name, &content_bytes);
        }
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

        let (headers, nonce) = build_signed_headers(&self.app_id, &self.app_secret, "POST", "/api/client/feedback", "", &body);
        let mut req = self
            .http
            .post(format!("{}/api/client/feedback", self.base_url))
            .header("Content-Type", format!("multipart/form-data; boundary={}", boundary))
            .body(body);
        for (k, v) in &headers {
            req = req.header(*k, v);
        }
        let resp = req.send()?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            if is_feedback_disabled_body(&text) {
                return Err(Box::new(FeedbackDisabledError));
            }
            return Err(format!("report feedback failed: {}", status).into());
        }
        let text = resp.text()?;
        self.verify_response_authz(&text, &nonce)?;
        Ok(())
    }

    pub fn download(&self, url: &str, dest_path: &Path, checksum: Option<&str>, signature: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
        let mut res = self.http.get(url).send()?.error_for_status()?;
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = File::create(dest_path)?;
        let mut hasher = Sha256::new();

        let mut buf = [0u8; 32 * 1024];
        loop {
            let read = res.read(&mut buf)?;
            if read == 0 {
                break;
            }
            out.write_all(&buf[..read])?;
            hasher.update(&buf[..read]);
        }

        if let Some(expected) = checksum {
            let got = format!("{:x}", hasher.finalize());
            if got != expected.to_lowercase() {
                return Err(format!("checksum mismatch: {} != {}", got, expected).into());
            }
        }
        if let (Some(sig), Some(chk)) = (signature, checksum) {
            if let Some(verify) = self.signature_verifier {
                if !verify(chk, sig) {
                    return Err("signature verification failed".into());
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod authz_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // Independently construct the canonical the server signs, to cross-check
    // authz_canonical / verify_authz_impl.
    fn server_canonical(now: i64, exp: i64, decision: &str, reason: &str) -> String {
        [
            "authz_v1".to_string(),
            "app_id:app-uuid".to_string(),
            "device_id:dev-1".to_string(),
            "nonce:n1".to_string(),
            format!("decision:{}", decision),
            format!("reason:{}", reason),
            format!("issued_at:{}", now),
            format!("expires_at:{}", exp),
            "key_id:k1".to_string(),
        ]
        .join("\n")
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn authz_verifies_and_rejects_tampering() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pub_hex = hex::encode(sk.verifying_key().to_bytes());
        let mut keys = HashMap::new();
        keys.insert("k1".to_string(), pub_hex);
        let now = chrono::Utc::now().timestamp();
        let exp = now + 600;

        let mut env = AuthzEnvelope {
            decision: "allow".into(),
            nonce: "n1".into(),
            device_id: "dev-1".into(),
            issued_at: now,
            expires_at: exp,
            key_id: "k1".into(),
            reason: String::new(),
            signature: b64(&sk.sign(server_canonical(now, exp, "allow", "").as_bytes()).to_bytes()),
        };

        // valid -> accepted (proves canonical matches server format)
        assert!(verify_authz_impl(true, &keys, 120, "app-uuid", "dev-1", Some(&env), "n1").is_ok());
        // nonce mismatch
        assert!(verify_authz_impl(true, &keys, 120, "app-uuid", "dev-1", Some(&env), "wrong").is_err());
        // device mismatch
        assert!(verify_authz_impl(true, &keys, 120, "app-uuid", "other", Some(&env), "n1").is_err());
        // unknown key
        assert!(verify_authz_impl(true, &keys, 120, "app-uuid", "dev-1", Some(&AuthzEnvelope { key_id: "nope".into(), ..env.clone() }), "n1").is_err());
        // forged signature
        let forged = AuthzEnvelope { signature: b64(&[0u8; 64]), ..env.clone() };
        assert!(verify_authz_impl(true, &keys, 120, "app-uuid", "dev-1", Some(&forged), "n1").is_err());
        // deny verdict (properly signed) -> denied
        let deny = AuthzEnvelope {
            decision: "deny".into(),
            reason: "blocked".into(),
            signature: b64(&sk.sign(server_canonical(now, exp, "deny", "blocked").as_bytes()).to_bytes()),
            ..env.clone()
        };
        assert!(verify_authz_impl(true, &keys, 120, "app-uuid", "dev-1", Some(&deny), "n1").is_err());
        // expired
        env.expires_at = now - 9000;
        env.signature = b64(&sk.sign(server_canonical(now, now - 9000, "allow", "").as_bytes()).to_bytes());
        assert!(verify_authz_impl(true, &keys, 120, "app-uuid", "dev-1", Some(&env), "n1").is_err());
        // missing envelope
        assert!(verify_authz_impl(true, &keys, 120, "app-uuid", "dev-1", None, "n1").is_err());
        // require_authz off -> no-op
        assert!(verify_authz_impl(false, &keys, 120, "app-uuid", "dev-1", None, "n1").is_ok());
    }
}
