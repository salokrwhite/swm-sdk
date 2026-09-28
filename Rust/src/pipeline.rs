use crate::client::ClientInner;
use crate::crypto::{
    base64url_encode, canonical_query, encrypt_request_body, random_uuid, sha256, sha256_hex,
    verify_ed25519,
};
use crate::error::{Error, ErrorKind, Result};
use crate::models::HardwareEvidence;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::time::sleep;

const HEADER_APP_ID: &str = "X-App-Id";
const HEADER_TIMESTAMP: &str = "X-Timestamp";
const HEADER_NONCE: &str = "X-Nonce";
const HEADER_CAPABILITY: &str = "X-Authz-Capability";
const HEADER_RELEASE_ID: &str = "X-Client-Release-Id";
const HEADER_CLIENT_VERSION: &str = "X-Client-Version";
const HEADER_VERSION_CODE: &str = "X-Client-Version-Code";
const HEADER_SESSION: &str = "X-SWM-Session";
const HEADER_DPOP: &str = "X-SWM-DPoP";
const HEADER_BODY_ENC: &str = "X-SWM-Body-Enc";
const HEADER_ONLINE_KEY_ID: &str = "X-SWM-Online-Key-Id";

#[derive(Clone, Debug)]
pub(crate) struct ProtocolKey {
    pub(crate) key_id: String,
    pub(crate) public_key: String,
    pub(crate) refresh_after: i64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DeviceAuthRegistration {
    pub(crate) install_id: String,
    pub(crate) key_id: String,
    pub(crate) key_thumbprint: String,
    pub(crate) public_key_sec1: String,
    pub(crate) credential_version: String,
    pub(crate) challenge: Option<String>,
    pub(crate) hardware_evidence: HardwareEvidence,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum OperationClass {
    TrustedTime,
    OnlineKey,
    UpdateCheck,
    Heartbeat,
    Events,
    Feedback,
    Enrollment,
    Rotation,
    OperationAuthorization,
    OperationConsume,
    Firmware,
    Debug,
}

#[derive(Clone, Copy)]
struct RequestPolicy {
    timeout: Duration,
    retries: usize,
    backoff: Duration,
    backoff_max: Duration,
    deadline: Duration,
}

fn policy(operation: OperationClass) -> RequestPolicy {
    match operation {
        OperationClass::TrustedTime | OperationClass::OnlineKey => RequestPolicy {
            timeout: Duration::from_secs(10),
            retries: 2,
            backoff: Duration::from_secs(1),
            backoff_max: Duration::from_secs(4),
            deadline: Duration::from_secs(40),
        },
        OperationClass::UpdateCheck => RequestPolicy {
            timeout: Duration::from_secs(15),
            retries: 2,
            backoff: Duration::from_millis(1500),
            backoff_max: Duration::from_secs(6),
            deadline: Duration::from_secs(60),
        },
        OperationClass::Heartbeat => RequestPolicy {
            timeout: Duration::from_secs(8),
            retries: 2,
            backoff: Duration::from_secs(1),
            backoff_max: Duration::from_secs(4),
            deadline: Duration::from_secs(30),
        },
        OperationClass::OperationAuthorization => RequestPolicy {
            timeout: Duration::from_secs(10),
            retries: 2,
            backoff: Duration::from_secs(1),
            backoff_max: Duration::from_secs(4),
            deadline: Duration::from_secs(36),
        },
        OperationClass::OperationConsume => RequestPolicy {
            timeout: Duration::from_secs(10),
            retries: 1,
            backoff: Duration::from_secs(1),
            backoff_max: Duration::from_secs(2),
            deadline: Duration::from_secs(24),
        },
        _ => RequestPolicy {
            timeout: Duration::from_secs(10),
            retries: 1,
            backoff: Duration::from_millis(500),
            backoff_max: Duration::from_secs(1),
            deadline: Duration::from_secs(24),
        },
    }
}

pub(crate) struct ProtocolRequest {
    pub(crate) operation: OperationClass,
    pub(crate) method: reqwest::Method,
    pub(crate) path: String,
    pub(crate) query: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    pub(crate) encrypt_body: bool,
    pub(crate) require_session: bool,
    pub(crate) require_trusted_time: bool,
    pub(crate) require_online_key: bool,
    pub(crate) content_type: Option<String>,
}

pub(crate) struct ProtocolResponse {
    pub(crate) status: reqwest::StatusCode,
    pub(crate) body: Vec<u8>,
    pub(crate) nonce: String,
    pub(crate) headers: reqwest::header::HeaderMap,
}

pub(crate) struct TrustedClock {
    state: Mutex<ClockState>,
}

struct ClockState {
    initialized: bool,
    anchor_server_millis: i64,
    anchor_instant: Instant,
}

impl Default for TrustedClock {
    fn default() -> Self {
        Self {
            state: Mutex::new(ClockState {
                initialized: false,
                anchor_server_millis: 0,
                anchor_instant: Instant::now(),
            }),
        }
    }
}

impl TrustedClock {
    pub(crate) fn is_initialized(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.initialized)
            .unwrap_or(false)
    }

    pub(crate) fn now_unix_milliseconds(&self) -> i64 {
        let state = match self.state.lock() {
            Ok(value) => value,
            Err(_) => return 0,
        };
        if !state.initialized {
            return 0;
        }
        state.anchor_server_millis + state.anchor_instant.elapsed().as_millis() as i64
    }

    pub(crate) fn now_unix_seconds(&self) -> i64 {
        let value = self.now_unix_milliseconds();
        if value <= 0 { 0 } else { value / 1000 }
    }

    pub(crate) fn set_authoritative(
        &self,
        server_millis: i64,
        started: Instant,
        received: Instant,
    ) -> Result<()> {
        if !(1_577_836_800_000..=4_102_444_800_000).contains(&server_millis) {
            return Err(Error::new(
                ErrorKind::Clock,
                "signed server time is outside the accepted range",
            ));
        }
        let round_trip = received.saturating_duration_since(started);
        if round_trip > Duration::from_secs(5) {
            return Err(Error::new(
                ErrorKind::Clock,
                "signed server time round trip is too slow",
            ));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Clock, "clock lock poisoned"))?;
        state.anchor_server_millis = server_millis + round_trip.as_millis() as i64 / 2;
        state.anchor_instant = received;
        state.initialized = true;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ServerTimeManifest {
    manifest_version: String,
    app_id: String,
    release_id: String,
    nonce: String,
    server_time_ms: i64,
    expires_at_ms: i64,
    root_trust_key_id: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize)]
struct OnlineKeyManifest {
    manifest_version: String,
    purpose: String,
    app_id: String,
    release_id: String,
    key_id: String,
    public_key: String,
    root_trust_key_id: String,
    root_trust_signature: String,
    issued_at: i64,
    refresh_after: i64,
}

#[derive(Clone, Debug, Deserialize)]
struct AuthzEnvelope {
    version: String,
    decision: String,
    release_id: String,
    device_id: String,
    nonce: String,
    data_sha256: String,
    session: Option<String>,
    issued_at: i64,
    expires_at: i64,
    key_id: String,
    reason: Option<String>,
    signature: String,
}

#[derive(Deserialize)]
struct AuthzCarrier<'a> {
    #[serde(borrow)]
    data: &'a RawValue,
    authz: AuthzEnvelope,
}

impl ClientInner {
    pub(crate) async fn send(&self, request: ProtocolRequest) -> Result<ProtocolResponse> {
        if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::new(ErrorKind::Configuration, "client is closed"));
        }
        if request.require_trusted_time && !self.clock.is_initialized() {
            self.refresh_trusted_time().await?;
        }
        if request.require_online_key {
            self.refresh_online_keys(false).await?;
        }
        if request.require_session {
            self.ensure_session()?;
        }
        let policy = policy(request.operation);
        let started = Instant::now();
        let mut last_transport = None;
        for attempt in 0..=policy.retries {
            if policy.deadline > Duration::ZERO
                && started.elapsed() + policy.timeout > policy.deadline
            {
                break;
            }
            match self.send_attempt(&request, policy.timeout).await {
                Ok(response) => {
                    if is_transient(response.status.as_u16()) && attempt < policy.retries {
                        let delay = parse_retry_after(&response.headers)
                            .unwrap_or_else(|| backoff(policy, attempt));
                        sleep(delay).await;
                        continue;
                    }
                    return Ok(response);
                }
                Err(error) => {
                    last_transport = Some(error);
                    if attempt >= policy.retries {
                        break;
                    }
                    sleep(backoff(policy, attempt)).await;
                }
            }
        }
        Err(last_transport
            .unwrap_or_else(|| Error::new(ErrorKind::Timeout, "request deadline exceeded")))
    }

    async fn send_attempt(
        &self,
        request: &ProtocolRequest,
        timeout: Duration,
    ) -> Result<ProtocolResponse> {
        let mut uri = self.base_url.clone();
        uri.set_path(&request.path);
        uri.set_query(None);
        if !request.query.is_empty() {
            uri.query_pairs_mut().extend_pairs(&request.query);
        }
        let timestamp = if request.require_trusted_time {
            self.clock.now_unix_seconds().to_string()
        } else {
            time::OffsetDateTime::now_utc().unix_timestamp().to_string()
        };
        let nonce = random_uuid();
        let mut body = request.body.clone();
        let mut builder = self
            .http
            .request(request.method.clone(), uri.clone())
            .header(HEADER_APP_ID, &self.options.app_id)
            .header(HEADER_TIMESTAMP, &timestamp)
            .header(HEADER_NONCE, &nonce)
            .header(HEADER_CAPABILITY, "v3")
            .header(HEADER_RELEASE_ID, &self.options.release_id)
            .header(HEADER_CLIENT_VERSION, &self.options.version)
            .header(
                HEADER_VERSION_CODE,
                self.options
                    .version_code
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            );
        let mut session = String::new();
        if request.require_session {
            session = self.ensure_session()?;
            builder = builder.header(HEADER_SESSION, &session);
        }
        if request.require_online_key {
            let key = self.current_key()?;
            let proof = self.create_dpop(request.method.as_ref(), uri.as_str(), &session, &body)?;
            builder = builder.header(HEADER_DPOP, proof);
            if request.encrypt_body {
                body = encrypt_request_body(
                    request.method.as_str(),
                    uri.path(),
                    &canonical_query(&uri),
                    timestamp.parse().unwrap_or_default(),
                    &nonce,
                    &self.options.app_id,
                    &self.options.release_id,
                    &self.options.version,
                    self.options.version_code,
                    &key.key_id,
                    &key.public_key,
                    &body,
                )?;
                builder = builder
                    .header(HEADER_BODY_ENC, "x25519-aes-gcm-v1")
                    .header(HEADER_ONLINE_KEY_ID, key.key_id);
            }
        }
        if let Some(content_type) = &request.content_type {
            builder = builder.header(reqwest::header::CONTENT_TYPE, content_type);
        } else if !body.is_empty() {
            builder = builder.header(
                reqwest::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            );
        }
        let response = tokio::time::timeout(timeout, builder.body(body).send())
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "request timed out"))??;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await?.to_vec();
        Ok(ProtocolResponse {
            status,
            body,
            nonce,
            headers,
        })
    }

    pub(crate) async fn send_and_verify<T: for<'de> Deserialize<'de>>(
        &self,
        request: ProtocolRequest,
    ) -> Result<T> {
        let response = self.send(request).await?;
        self.throw_if_error(&response)?;
        let data = self.verify_authz(&response).await?;
        serde_json::from_slice(&data).map_err(Error::from)
    }

    pub(crate) async fn verify_authz(&self, response: &ProtocolResponse) -> Result<Vec<u8>> {
        let carrier: AuthzCarrier<'_> = serde_json::from_slice(&response.body)
            .map_err(|_| Error::new(ErrorKind::Protocol, "Authz v3 carrier is invalid"))?;
        let data = carrier.data.get().as_bytes().to_vec();
        let envelope = carrier.authz;
        let now = self.clock.now_unix_seconds();
        if envelope.version != "authz_v3"
            || envelope.decision != "allow"
            || envelope.release_id != self.options.release_id
            || envelope.device_id != self.expected_device_id().await?
            || envelope.nonce != response.nonce
            || envelope.key_id.is_empty()
            || envelope.issued_at <= 0
            || envelope.expires_at <= envelope.issued_at
            || envelope.expires_at - envelope.issued_at > 900
            || envelope.issued_at > now + 120
            || envelope.expires_at < now - 120
        {
            return Err(Error::new(
                ErrorKind::Unauthorized,
                "Authz v3 response identity or lifetime is invalid",
            ));
        }
        let key = self.find_key(&envelope.key_id).ok_or_else(|| {
            Error::new(ErrorKind::Unauthorized, "Authz v3 response key is unknown")
        })?;
        if !crate::crypto::constant_time_eq(&envelope.data_sha256, &sha256_hex(&data)) {
            return Err(Error::new(
                ErrorKind::Integrity,
                "Authz v3 response data hash is invalid",
            ));
        }
        let canonical = [
            "authz_v3".to_string(),
            format!("app_id:{}", self.options.app_id),
            format!("release_id:{}", envelope.release_id),
            format!("device_id:{}", envelope.device_id),
            format!("nonce:{}", envelope.nonce),
            format!("decision:{}", envelope.decision),
            format!("reason:{}", envelope.reason.unwrap_or_default()),
            format!("data_sha256:{}", envelope.data_sha256),
            format!("session:{}", envelope.session.clone().unwrap_or_default()),
            format!("issued_at:{}", envelope.issued_at),
            format!("expires_at:{}", envelope.expires_at),
            format!("key_id:{}", envelope.key_id),
        ]
        .join("\n");
        if !verify_ed25519(&key.public_key, canonical.as_bytes(), &envelope.signature)? {
            return Err(Error::new(
                ErrorKind::Integrity,
                "Authz v3 response signature is invalid",
            ));
        }
        if let Some(session) = envelope.session {
            if !session.is_empty() {
                self.install_session(session, envelope.expires_at);
            }
        }
        self.note_verified_interaction();
        Ok(data)
    }

    pub(crate) fn throw_if_error(&self, response: &ProtocolResponse) -> Result<()> {
        if response.status.is_success() {
            return Ok(());
        }
        let body = String::from_utf8_lossy(&response.body).to_string();
        let mut code = String::new();
        let mut message = response
            .status
            .canonical_reason()
            .unwrap_or("request failed")
            .to_string();
        let mut minimum_version = None;
        if let Ok(root) = serde_json::from_slice::<serde_json::Value>(&response.body) {
            if let Some(error) = root.get("error") {
                if let Some(object) = error.as_object() {
                    code = object
                        .get("code")
                        .and_then(|value| value.as_str())
                        .unwrap_or("")
                        .to_string();
                    message = object
                        .get("message")
                        .and_then(|value| value.as_str())
                        .unwrap_or(&message)
                        .to_string();
                    minimum_version = object
                        .get("minimum_supported_version")
                        .and_then(|value| value.as_str())
                        .map(str::to_string);
                } else if let Some(value) = error.as_str() {
                    message = value.to_string();
                    if looks_like_code(value) {
                        code = value.to_string();
                    }
                }
            } else {
                code = root
                    .get("code")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .to_string();
                message = root
                    .get("message")
                    .and_then(|value| value.as_str())
                    .unwrap_or(&message)
                    .to_string();
            }
        }
        let kind = match code.as_str() {
            "device_blocked" => ErrorKind::DeviceBlocked,
            "client_version_unsupported" => ErrorKind::UnsupportedVersion,
            "update_region_blocked" => ErrorKind::UpdateRegionBlocked,
            "feedback_disabled" => ErrorKind::FeedbackDisabled,
            value if value.starts_with("release_integrity_") => ErrorKind::Integrity,
            value
                if value.starts_with("operation_auth_")
                    || value.starts_with("operation_grant_") =>
            {
                ErrorKind::OperationAuthorization
            }
            _ if response.status.as_u16() == 429 => ErrorKind::RateLimit,
            _ if response.status.as_u16() == 401 => ErrorKind::Session,
            _ if response.status.as_u16() == 403 => ErrorKind::Unauthorized,
            _ if response.status.is_client_error() => ErrorKind::Validation,
            _ => ErrorKind::Api,
        };
        let mut error = Error::new(kind, message)
            .with_status(response.status.as_u16())
            .with_response(body);
        if !code.is_empty() {
            error = error.with_code(code);
        }
        if let Some(value) = minimum_version {
            error.minimum_supported_version = Some(value);
        }
        Err(error)
    }

    pub(crate) fn create_dpop(
        &self,
        method: &str,
        absolute_url: &str,
        session: &str,
        body: &[u8],
    ) -> Result<String> {
        let identity = self
            .identity
            .try_lock()
            .map_err(|_| Error::new(ErrorKind::Identity, "identity lock poisoned"))?
            .clone()
            .ok_or_else(|| Error::new(ErrorKind::Identity, "identity is unavailable"))?;
        let now = self.clock.now_unix_seconds();
        if now <= 0 {
            return Err(Error::new(ErrorKind::Clock, "trusted time is unavailable"));
        }
        let header = serde_json::json!({
            "alg": "ES256",
            "kid": identity.key_id,
            "typ": "swm-dpop+jwt"
        });
        let payload = serde_json::json!({
            "app_id": self.options.app_id,
            "ath": base64url_encode(&sha256(session.as_bytes())),
            "body_sha256": sha256_hex(body),
            "channel": self.options.channel,
            "device_id": self.options.device_id.as_deref().unwrap_or(&identity.device_id),
            "exp": now + 60,
            "htm": method.to_ascii_uppercase(),
            "htu": absolute_url,
            "iat": now,
            "install_id": identity.install_id,
            "jti": random_uuid(),
            "pcid": self.options.device_id.as_deref().unwrap_or(&identity.device_id),
            "release_id": self.options.release_id
        });
        let signing_input = format!(
            "{}.{}",
            base64url_encode(&serde_json::to_vec(&header)?),
            base64url_encode(&serde_json::to_vec(&payload)?)
        );
        let signature = identity.sign_digest(&sha256(signing_input.as_bytes()))?;
        Ok(format!("{signing_input}.{}", base64url_encode(&signature)))
    }

    pub(crate) fn current_key(&self) -> Result<ProtocolKey> {
        let key = self
            .current_key
            .lock()
            .map_err(|_| Error::new(ErrorKind::Session, "key lock poisoned"))?
            .clone()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Session,
                    "online authorization key is unavailable",
                )
            })?;
        if self.clock.is_initialized() && self.clock.now_unix_seconds() >= key.refresh_after {
            return Err(Error::new(
                ErrorKind::Session,
                "online authorization key has expired",
            ));
        }
        Ok(key)
    }

    fn find_key(&self, key_id: &str) -> Option<ProtocolKey> {
        if let Ok(current) = self.current_key.lock() {
            if let Some(current) = current.as_ref() {
                if current.key_id == key_id {
                    return Some(current.clone());
                }
            }
        }
        self.previous_keys
            .lock()
            .ok()
            .and_then(|keys| keys.iter().rev().find(|key| key.key_id == key_id).cloned())
    }

    fn install_key(&self, next: ProtocolKey) -> Result<()> {
        let mut current = self
            .current_key
            .lock()
            .map_err(|_| Error::new(ErrorKind::Integrity, "key lock poisoned"))?;
        let mut previous = self
            .previous_keys
            .lock()
            .map_err(|_| Error::new(ErrorKind::Integrity, "key lock poisoned"))?;
        if let Some(existing) = current.as_ref() {
            if existing.key_id == next.key_id && existing.public_key != next.public_key {
                return Err(Error::new(
                    ErrorKind::Integrity,
                    "online key id was rebound to different key material",
                ));
            }
            if existing.key_id != next.key_id {
                previous.push(existing.clone());
                while previous.len() > 4 {
                    previous.remove(0);
                }
            }
        }
        if let Some(index) = previous.iter().position(|key| key.key_id == next.key_id) {
            if previous[index].public_key != next.public_key {
                return Err(Error::new(
                    ErrorKind::Integrity,
                    "online key id was rebound to different key material",
                ));
            }
            previous.remove(index);
        }
        *current = Some(next);
        Ok(())
    }

    fn has_fresh_key(&self) -> bool {
        self.current_key
            .lock()
            .ok()
            .and_then(|key| key.as_ref().cloned())
            .map(|key| {
                self.clock.is_initialized()
                    && self.clock.now_unix_seconds() < key.refresh_after - 300
            })
            .unwrap_or(false)
    }

    fn can_use_current_key(&self) -> bool {
        self.current_key
            .lock()
            .ok()
            .and_then(|key| key.as_ref().cloned())
            .map(|key| {
                self.clock.is_initialized() && self.clock.now_unix_seconds() < key.refresh_after
            })
            .unwrap_or(false)
    }

    pub(crate) async fn refresh_online_keys(&self, force: bool) -> Result<()> {
        if !force && self.has_fresh_key() {
            return Ok(());
        }
        let _guard = self.key_refresh.lock().await;
        if !force && self.has_fresh_key() {
            return Ok(());
        }
        if !self.clock.is_initialized() {
            self.refresh_trusted_time().await?;
        }
        let response = match Box::pin(self.send(ProtocolRequest {
            operation: OperationClass::OnlineKey,
            method: reqwest::Method::GET,
            path: "/api/client/key-manifest".into(),
            query: Vec::new(),
            body: Vec::new(),
            encrypt_body: false,
            require_session: false,
            require_trusted_time: true,
            require_online_key: false,
            content_type: None,
        }))
        .await
        {
            Ok(response) => response,
            Err(_error) if self.can_use_current_key() => return Ok(()),
            Err(error) => return Err(error),
        };
        if let Err(error) = self.throw_if_error(&response) {
            if self.can_use_current_key() && is_transient(response.status.as_u16()) {
                return Ok(());
            }
            return Err(error);
        }
        let manifest: OnlineKeyManifest = serde_json::from_slice(&response.body)?;
        if manifest.manifest_version != "online_key_manifest_v1"
            || manifest.purpose != "online_body"
            || manifest.app_id != self.options.app_id
            || manifest.release_id != self.options.release_id
            || manifest.root_trust_key_id != self.options.root_trust_key_id
            || manifest.key_id.is_empty()
            || manifest.public_key.is_empty()
            || manifest.root_trust_signature.is_empty()
            || manifest.issued_at <= 0
            || manifest.refresh_after <= manifest.issued_at
            || manifest.refresh_after - manifest.issued_at > 30 * 24 * 60 * 60
        {
            return Err(Error::new(
                ErrorKind::Integrity,
                "online key manifest identity or lifetime is invalid",
            ));
        }
        let now = self.clock.now_unix_seconds();
        if manifest.issued_at > now + 120 || manifest.refresh_after < now - 120 {
            return Err(Error::new(
                ErrorKind::Integrity,
                "online key manifest is outside its accepted lifetime",
            ));
        }
        let canonical = [
            manifest.manifest_version,
            format!("purpose:{}", manifest.purpose),
            format!("app_id:{}", manifest.app_id),
            format!("release_id:{}", manifest.release_id),
            format!("key_id:{}", manifest.key_id),
            format!("public_key:{}", manifest.public_key),
            format!("root_trust_key_id:{}", manifest.root_trust_key_id),
            format!("issued_at:{}", manifest.issued_at),
            format!("refresh_after:{}", manifest.refresh_after),
        ]
        .join("\n");
        if !verify_ed25519(
            &self.options.root_trust_public_key,
            canonical.as_bytes(),
            &manifest.root_trust_signature,
        )? {
            return Err(Error::new(
                ErrorKind::Integrity,
                "online key manifest root signature is invalid",
            ));
        }
        self.install_key(ProtocolKey {
            key_id: manifest.key_id,
            public_key: manifest.public_key,
            refresh_after: manifest.refresh_after,
        })
    }

    pub(crate) async fn refresh_trusted_time(&self) -> Result<()> {
        let started = Instant::now();
        let response = Box::pin(self.send(ProtocolRequest {
            operation: OperationClass::TrustedTime,
            method: reqwest::Method::GET,
            path: "/api/client/time".into(),
            query: Vec::new(),
            body: Vec::new(),
            encrypt_body: false,
            require_session: false,
            require_trusted_time: false,
            require_online_key: false,
            content_type: None,
        }))
        .await?;
        let received = Instant::now();
        self.throw_if_error(&response)?;
        let manifest: ServerTimeManifest = serde_json::from_slice(&response.body)?;
        if manifest.manifest_version != "server_time_v1"
            || manifest.app_id != self.options.app_id
            || manifest.release_id != self.options.release_id
            || manifest.nonce != response.nonce
            || manifest.root_trust_key_id != self.options.root_trust_key_id
            || manifest.signature.is_empty()
            || manifest.server_time_ms <= 0
            || manifest.expires_at_ms <= manifest.server_time_ms
            || manifest.expires_at_ms - manifest.server_time_ms > 60_000
        {
            return Err(Error::new(
                ErrorKind::Clock,
                "signed server time identity or lifetime is invalid",
            ));
        }
        let canonical = [
            "server_time_v1".to_string(),
            format!("app_id:{}", manifest.app_id),
            format!("release_id:{}", manifest.release_id),
            format!("nonce:{}", manifest.nonce),
            format!("server_time_ms:{}", manifest.server_time_ms),
            format!("expires_at_ms:{}", manifest.expires_at_ms),
            format!("root_trust_key_id:{}", manifest.root_trust_key_id),
        ]
        .join("\n");
        if !verify_ed25519(
            &self.options.root_trust_public_key,
            canonical.as_bytes(),
            &manifest.signature,
        )? {
            return Err(Error::new(
                ErrorKind::Clock,
                "signed server time signature is invalid",
            ));
        }
        self.clock
            .set_authoritative(manifest.server_time_ms, started, received)?;
        self.note_verified_interaction();
        Ok(())
    }
}

fn is_transient(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

fn backoff(policy: RequestPolicy, attempt: usize) -> Duration {
    if policy.backoff.is_zero() {
        return Duration::ZERO;
    }
    policy
        .backoff
        .saturating_mul(1u32 << attempt.min(16))
        .min(policy.backoff_max.max(policy.backoff))
}

fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let date = httpdate::parse_http_date(value).ok()?;
    let now = std::time::SystemTime::now();
    Some(date.duration_since(now).unwrap_or(Duration::ZERO))
}

fn looks_like_code(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use crate::options::ClientOptions;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use std::time::Instant;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[tokio::test]
    async fn verifies_authz_v3_and_updates_session() {
        let app_id = "00000000-0000-0000-0000-000000001001";
        let release_id = "00000000-0000-0000-0000-000000001002";
        let device_id = "device-1001";
        let nonce = "00000000-0000-0000-0000-000000001003";
        let key_id = "key-1001";
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let client = Client::new(
            ClientOptions::builder()
                .base_url("https://swm.example.test")
                .app_id(app_id)
                .release_id(release_id)
                .version("1.0.0")
                .root_trust_key_id("root-1")
                .root_trust_public_key(hex::encode([0u8; 32]))
                .device_id(device_id)
                .storage_directory(tempfile::tempdir().unwrap().keep())
                .build()
                .unwrap(),
        )
        .unwrap();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        client
            .inner
            .clock
            .set_authoritative(now * 1000, Instant::now(), Instant::now())
            .unwrap();
        *client.inner.current_key.lock().unwrap() = Some(ProtocolKey {
            key_id: key_id.into(),
            public_key: hex::encode(public_key),
            refresh_after: now + 3600,
        });
        let data = r#"{"ok":true}"#;
        let canonical = [
            "authz_v3".to_string(),
            format!("app_id:{app_id}"),
            format!("release_id:{release_id}"),
            format!("device_id:{device_id}"),
            format!("nonce:{nonce}"),
            "decision:allow".into(),
            "reason:".into(),
            format!("data_sha256:{}", sha256_hex(data.as_bytes())),
            "session:session-1001".into(),
            format!("issued_at:{now}"),
            format!("expires_at:{}", now + 600),
            format!("key_id:{key_id}"),
        ]
        .join("\n");
        let signature =
            crate::crypto::base64url_encode(&signing_key.sign(canonical.as_bytes()).to_bytes());
        let carrier = format!(
            r#"{{"data":{},"authz":{}}}"#,
            data,
            json!({
                "version": "authz_v3",
                "decision": "allow",
                "release_id": release_id,
                "device_id": device_id,
                "nonce": nonce,
                "data_sha256": sha256_hex(data.as_bytes()),
                "session": "session-1001",
                "issued_at": now,
                "expires_at": now + 600,
                "key_id": key_id,
                "signature": signature
            })
        );
        let verified = client
            .inner
            .verify_authz(&ProtocolResponse {
                status: reqwest::StatusCode::OK,
                body: carrier.into_bytes(),
                nonce: nonce.into(),
                headers: reqwest::header::HeaderMap::new(),
            })
            .await
            .unwrap();
        assert_eq!(verified, data.as_bytes());
        assert_eq!(client.session_token().as_deref(), Some("session-1001"));
    }

    #[tokio::test]
    async fn refreshes_time_and_online_keys_over_http() {
        let app_id = "00000000-0000-0000-0000-000000001101";
        let release_id = "00000000-0000-0000-0000-000000001102";
        let root_key = SigningKey::from_bytes(&[0x44; 32]);
        let root_public = root_key.verifying_key().to_bytes();
        let server = MockServer::start().await;
        let time_responder = ServerTimeResponder {
            app_id: app_id.into(),
            release_id: release_id.into(),
            root_key_id: "root-1101".into(),
            root_key: SigningKey::from_bytes(&[0x44; 32]),
        };
        Mock::given(method("GET"))
            .and(path("/api/client/time"))
            .respond_with(time_responder)
            .mount(&server)
            .await;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut key_manifest = json!({
            "manifest_version": "online_key_manifest_v1",
            "purpose": "online_body",
            "app_id": app_id,
            "release_id": release_id,
            "key_id": "online-key-1101",
            "public_key": hex::encode([0x55u8; 32]),
            "root_trust_key_id": "root-1101",
            "issued_at": now - 1,
            "refresh_after": now + 3600
        });
        let canonical = [
            "online_key_manifest_v1".to_string(),
            "purpose:online_body".to_string(),
            format!("app_id:{app_id}"),
            format!("release_id:{release_id}"),
            "key_id:online-key-1101".to_string(),
            format!("public_key:{}", hex::encode([0x55u8; 32])),
            "root_trust_key_id:root-1101".to_string(),
            format!("issued_at:{}", now - 1),
            format!("refresh_after:{}", now + 3600),
        ]
        .join("\n");
        key_manifest["root_trust_signature"] = json!(crate::crypto::base64url_encode(
            &root_key.sign(canonical.as_bytes()).to_bytes()
        ));
        Mock::given(method("GET"))
            .and(path("/api/client/key-manifest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(key_manifest))
            .mount(&server)
            .await;
        let client = Client::new(
            ClientOptions::builder()
                .base_url(server.uri())
                .app_id(app_id)
                .release_id(release_id)
                .version("1.0.0")
                .root_trust_key_id("root-1101")
                .root_trust_public_key(hex::encode(root_public))
                .allow_insecure_http(true)
                .storage_directory(tempfile::tempdir().unwrap().keep())
                .build()
                .unwrap(),
        )
        .unwrap();
        client.refresh_online_keys().await.unwrap();
        assert!(client.inner.current_key.lock().unwrap().is_some());
    }

    struct ServerTimeResponder {
        app_id: String,
        release_id: String,
        root_key_id: String,
        root_key: SigningKey,
    }

    impl Respond for ServerTimeResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let nonce = request
                .headers
                .get("X-Nonce")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;
            let canonical = [
                "server_time_v1".to_string(),
                format!("app_id:{}", self.app_id),
                format!("release_id:{}", self.release_id),
                format!("nonce:{nonce}"),
                format!("server_time_ms:{now}"),
                format!("expires_at_ms:{}", now + 30_000),
                format!("root_trust_key_id:{}", self.root_key_id),
            ]
            .join("\n");
            ResponseTemplate::new(200).set_body_json(json!({
                "manifest_version": "server_time_v1",
                "app_id": self.app_id,
                "release_id": self.release_id,
                "nonce": nonce,
                "server_time_ms": now,
                "expires_at_ms": now + 30_000,
                "root_trust_key_id": self.root_key_id,
                "signature": crate::crypto::base64url_encode(
                    &self.root_key.sign(canonical.as_bytes()).to_bytes()
                )
            }))
        }
    }
}
