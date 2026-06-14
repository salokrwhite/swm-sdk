use reqwest::blocking::Client as HttpClient;
use reqwest::blocking::multipart;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;
use std::thread::sleep;
use std::thread;

#[derive(Debug)]
pub struct FeedbackDisabledError;

impl std::fmt::Display for FeedbackDisabledError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "feedback disabled")
    }
}

impl std::error::Error for FeedbackDisabledError {}

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
    app_key: String,
    pub channel: String,
    pub platform: String,
    pub arch: String,
    pub device_id: String,
    pub attributes: serde_json::Value,
    pub retries: u32,
    pub backoff_ms: u64,
    pub signature_verifier: Option<fn(&str, &str) -> bool>,
    http: HttpClient,
}

#[derive(Serialize)]
struct UpdateCheckRequest<'a> {
    app_key: &'a str,
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
    app_key: &'a str,
    device_id: &'a str,
    event_name: &'a str,
    event_time: String,
    channel_code: &'a str,
    properties: serde_json::Value,
    attributes: &'a serde_json::Value,
}

impl Client {
    pub fn new(base_url: &str, app_key: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            app_key: app_key.to_string(),
            http: HttpClient::new(),
            attributes: serde_json::json!({}),
            retries: 2,
            backoff_ms: 500,
            signature_verifier: None,
            ..Default::default()
        }
    }

    fn post_with_retry<T: serde::Serialize>(&self, path: &str, payload: &T) -> Result<reqwest::blocking::Response, reqwest::Error> {
        let mut last_err = None;
        for attempt in 0..=self.retries {
            let res = self.http.post(format!("{}/{}", self.base_url, path.trim_start_matches('/'))).json(payload).send();
            match res {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    last_err = Some(err);
                    let backoff = self.backoff_ms * (1u64 << attempt);
                    sleep(Duration::from_millis(backoff));
                }
            }
        }
        Err(last_err.unwrap())
    }

    pub fn check_update(&self, current_version: &str, version_code: Option<i32>) -> Result<UpdateCheckResponse, reqwest::Error> {
        let req = UpdateCheckRequest {
            app_key: &self.app_key,
            channel_code: &self.channel,
            current_version,
            version_code,
            platform: &self.platform,
            arch: &self.arch,
            device_id: &self.device_id,
            attributes: &self.attributes,
        };

        let res = self.post_with_retry("/api/client/update-check", &req)?
            .error_for_status()?;

        let out = res.json::<UpdateCheckResponse>()?;
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
        let app_key = self.app_key.clone();
        let on_event = Arc::new(on_event);
        let on_error = on_error.map(Arc::new);
        thread::spawn(move || {
            let mut backoff = options.reconnect_backoff_ms.max(300);
            let max_backoff = options.reconnect_max_backoff_ms.max(backoff);
            while !stop_clone.load(Ordering::Relaxed) {
                let mut params = vec![
                    ("app_key".to_string(), app_key.clone()),
                    ("channel_code".to_string(), channel.clone()),
                    ("platform".to_string(), platform.clone()),
                    ("arch".to_string(), arch.clone()),
                    ("device_id".to_string(), device_id.clone()),
                ];
                if let Some(v) = options.current_version.clone() {
                    params.push(("current_version".to_string(), v));
                }
                if let Some(v) = options.version_code {
                    params.push(("version_code".to_string(), v.to_string()));
                }
                let query = serde_urlencoded::to_string(params).unwrap_or_default();
                let url = format!("{}/api/client/updates/stream?{}", base_url, query);
                match client.get(url).send() {
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
                            let text = resp.text().unwrap_or_default();
                            let mut event_type = String::new();
                            let mut data = String::new();
                            for line in text.lines() {
                                if stop_clone.load(Ordering::Relaxed) {
                                    return;
                                }
                                let clean = line.trim();
                                if clean.is_empty() {
                                    if !data.is_empty() && event_type != "connected" {
                                        if let Ok(evt) = serde_json::from_str::<UpdatePushEvent>(&data) {
                                            on_event(evt);
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

    pub fn report_event(&self, event_name: &str, properties: serde_json::Value) -> Result<(), reqwest::Error> {
        let event = Event {
            app_key: &self.app_key,
            device_id: &self.device_id,
            event_name,
            event_time: chrono::Utc::now().to_rfc3339(),
            channel_code: &self.channel,
            properties,
            attributes: &self.attributes,
        };

        self.post_with_retry("/api/client/events", &event)?
            .error_for_status()?;

        Ok(())
    }

    pub fn report_heartbeat(&self, app_version: Option<&str>, user_id: Option<&str>) -> Result<(), reqwest::Error> {
        let mut map = serde_json::Map::new();
        map.insert("app_key".to_string(), serde_json::Value::String(self.app_key.clone()));
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
        self.post_with_retry("/api/client/heartbeat", &payload)?
            .error_for_status()?;
        Ok(())
    }

    pub fn report_events(&self, events: serde_json::Value) -> Result<(), reqwest::Error> {
        let payload = serde_json::json!({
            "app_key": self.app_key,
            "events": events
        });
        self.post_with_retry("/api/client/events", &payload)?
            .error_for_status()?;
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

        let mut form = multipart::Form::new()
            .text("app_key", self.app_key.clone())
            .text("device_id", self.device_id.clone())
            .text("content", content.to_string());

        if !self.channel.is_empty() {
            form = form.text("channel_code", self.channel.clone());
        }
        if let Some(score) = rating {
            form = form.text("rating", score.to_string());
        }
        if let Some(value) = contact {
            if !value.trim().is_empty() {
                form = form.text("contact", value.to_string());
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
        if !self.attributes.is_null() && !self.attributes.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            if !merged.contains_key("attributes") {
                merged.insert("attributes".to_string(), self.attributes.clone());
            }
        }
        if !merged.is_empty() {
            let metadata_value = serde_json::Value::Object(merged);
            form = form.text("metadata", metadata_value.to_string());
            if let Some(app_version) = metadata_value.get("app_version") {
                form = form.text("app_version", app_version.to_string().trim_matches('"').to_string());
            }
        }

        for path in attachments {
            if !path.exists() {
                continue;
            }
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("attachment");
            let part = multipart::Part::file(path)?.file_name(file_name.to_string());
            form = form.part("attachments", part);
        }

        let resp = self.http
            .post(format!("{}/api/client/feedback", self.base_url))
            .multipart(form)
            .send()?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            if is_feedback_disabled_body(&body) {
                return Err(Box::new(FeedbackDisabledError));
            }
            return Err(format!("report feedback failed: {}", status).into());
        }

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
            if read == 0 { break; }
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
