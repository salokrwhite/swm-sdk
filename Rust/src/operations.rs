use crate::client::Client;
use crate::crypto::{random_bytes, sha256_hex};
use crate::error::{Error, ErrorKind, Result};
use crate::identity::DeviceIdentity;
use crate::models::{
    DeviceKeyRotationResult, EnrollmentTicket, Event, FeedbackRequest, FeedbackResult,
    HeartbeatResult, OperationAuthorizationRequest, OperationConsumptionReceipt, OperationGrant,
    UpdateInfo,
};
use crate::options::CheckUpdateOptions;
use crate::pipeline::{DeviceAuthRegistration, OperationClass, ProtocolRequest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize)]
struct UpdateCheckWireRequest {
    channel_code: String,
    current_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_code: Option<i32>,
    platform: String,
    arch: String,
    device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attributes: Option<HashMap<String, serde_json::Value>>,
    device_auth: DeviceAuthRegistration,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity_failure_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity_evidence_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity_manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity_files: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
struct DeviceRegistrationChallenge {
    challenge: String,
    expires_at: i64,
}

#[derive(Serialize)]
struct HeartbeatWireRequest {
    device_id: String,
    channel_code: String,
    app_version: String,
    platform: String,
    arch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attributes: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity_evidence_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity_manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity_files: Option<HashMap<String, String>>,
}

#[derive(Serialize)]
struct EventBatch {
    events: Vec<Event>,
}

#[derive(Serialize)]
struct EnrollmentWireRequest {
    audience: String,
}

#[derive(Serialize)]
struct DeviceKeyRotationWireRequest {
    new_device_auth: DeviceAuthRegistration,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_key_proof: Option<String>,
}

#[derive(Deserialize)]
struct DeviceKeyRotationChallenge {
    challenge: String,
    expires_at: i64,
    proof_digest: String,
}

#[derive(Deserialize)]
struct DeviceKeyRotationWireResponse {
    rotated: bool,
    registration_id: String,
    install_id: String,
    key_id: String,
}

#[derive(Serialize)]
struct OperationAuthorizationWireRequest {
    schema: String,
    operation: String,
    plan_sha256: String,
    step_count: u32,
    total_bytes: u64,
    consumer_challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity_manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_exe_sha256: Option<String>,
    consumer_module: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    consumer_module_sha256: Option<String>,
}

#[derive(Serialize)]
struct OperationConsumeWireRequest {
    schema: String,
    grant_id: String,
    operation: String,
    plan_sha256: String,
    step_count: u32,
    total_bytes: u64,
    consumer_challenge: String,
    issued_at: i64,
    expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity_manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_exe_sha256: Option<String>,
    consumer_module: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    consumer_module_sha256: Option<String>,
}

impl Client {
    pub async fn check_update(&self, options: CheckUpdateOptions) -> Result<UpdateInfo> {
        self.ensure_not_closed()?;
        let evidence = self.inner.host.get_evidence().await?;
        let mut challenge = None;
        for attempt in 0..2 {
            let device_auth = self.create_device_auth(challenge.clone()).await?;
            let payload = UpdateCheckWireRequest {
                channel_code: self.inner.options.channel.clone(),
                current_version: self.inner.options.version.clone(),
                version_code: self.inner.options.version_code,
                platform: self.inner.options.platform.clone(),
                arch: self.inner.options.arch.clone(),
                device_id: self.device_id().await?,
                user_id: options.user_id.clone(),
                attributes: options.attributes.clone(),
                device_auth,
                integrity_state: evidence.integrity_state.clone(),
                integrity_failure_code: evidence.integrity_failure_code.clone(),
                integrity_evidence_version: evidence.integrity_evidence_version,
                integrity_manifest_sha256: evidence.integrity_manifest_sha256.clone(),
                integrity_files: evidence.integrity_files.clone(),
            };
            let response = self
                .inner
                .send(ProtocolRequest {
                    operation: OperationClass::UpdateCheck,
                    method: reqwest::Method::POST,
                    path: "/api/client/update-check".into(),
                    query: Vec::new(),
                    body: serde_json::to_vec(&payload)?,
                    encrypt_body: true,
                    require_session: false,
                    require_trusted_time: true,
                    require_online_key: true,
                    content_type: None,
                })
                .await?;
            if response.status.as_u16() == 428 && attempt == 0 {
                let value: DeviceRegistrationChallenge = serde_json::from_slice(&response.body)?;
                if value.challenge.is_empty()
                    || value.expires_at <= self.inner.clock.now_unix_seconds()
                {
                    return Err(Error::new(
                        ErrorKind::Protocol,
                        "device registration challenge is missing or expired",
                    ));
                }
                challenge = Some(value.challenge);
                continue;
            }
            self.inner.throw_if_error(&response)?;
            let data = self.inner.verify_authz(&response).await?;
            let update: UpdateInfo = serde_json::from_slice(&data)?;
            self.set_host_policy_required(update.host_integrity_required);
            verify_update_artifact(&update, &self.inner.options)?;
            return Ok(update);
        }
        Err(Error::new(
            ErrorKind::Protocol,
            "device registration challenge retry was exhausted",
        ))
    }

    pub async fn report_heartbeat(
        &self,
        app_version: Option<String>,
        user_id: Option<String>,
        attributes: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<HeartbeatResult> {
        self.ensure_not_closed()?;
        let evidence = self.inner.host.get_evidence().await?;
        if self.host_policy_required() && evidence.integrity_state.as_deref() != Some("verified") {
            return Err(Error::new(
                ErrorKind::Integrity,
                evidence
                    .integrity_failure_code
                    .unwrap_or_else(|| "host_manifest_missing".into()),
            ));
        }
        let payload = HeartbeatWireRequest {
            device_id: self.device_id().await?,
            channel_code: self.inner.options.channel.clone(),
            app_version: app_version.unwrap_or_else(|| self.inner.options.version.clone()),
            platform: self.inner.options.platform.clone(),
            arch: self.inner.options.arch.clone(),
            user_id,
            attributes,
            integrity_evidence_version: evidence.integrity_evidence_version,
            integrity_manifest_sha256: evidence.integrity_manifest_sha256,
            integrity_files: evidence.integrity_files,
        };
        self.inner
            .send_and_verify(ProtocolRequest {
                operation: OperationClass::Heartbeat,
                method: reqwest::Method::POST,
                path: "/api/client/heartbeat".into(),
                query: Vec::new(),
                body: serde_json::to_vec(&payload)?,
                encrypt_body: true,
                require_session: true,
                require_trusted_time: true,
                require_online_key: true,
                content_type: None,
            })
            .await
    }

    pub async fn report_event(
        &self,
        event_name: String,
        properties: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<()> {
        self.report_events(vec![Event {
            device_id: Some(self.device_id().await?),
            event_name,
            event_time: time::OffsetDateTime::now_utc(),
            channel_code: Some(self.inner.options.channel.clone()),
            properties,
            attributes: None,
        }])
        .await
    }

    pub async fn report_events(&self, mut events: Vec<Event>) -> Result<()> {
        self.ensure_not_closed()?;
        if events.is_empty() {
            return Ok(());
        }
        for event in &mut events {
            if event.event_name.trim().is_empty() {
                return Err(Error::new(ErrorKind::Validation, "event_name is required"));
            }
            if event.device_id.is_none() {
                event.device_id = Some(self.device_id().await?);
            }
            if event.channel_code.is_none() {
                event.channel_code = Some(self.inner.options.channel.clone());
            }
            if event.event_time == time::OffsetDateTime::UNIX_EPOCH {
                event.event_time = time::OffsetDateTime::now_utc();
            }
        }
        let body = if events.len() == 1 {
            serde_json::to_vec(&events[0])?
        } else {
            serde_json::to_vec(&EventBatch { events })?
        };
        let _: serde_json::Value = self
            .inner
            .send_and_verify(ProtocolRequest {
                operation: OperationClass::Events,
                method: reqwest::Method::POST,
                path: "/api/client/events".into(),
                query: Vec::new(),
                body,
                encrypt_body: true,
                require_session: true,
                require_trusted_time: true,
                require_online_key: true,
                content_type: None,
            })
            .await?;
        Ok(())
    }

    pub async fn submit_feedback(&self, request: FeedbackRequest) -> Result<FeedbackResult> {
        self.ensure_not_closed()?;
        if request.content.trim().is_empty() {
            return Err(Error::new(
                ErrorKind::Validation,
                "feedback content is required",
            ));
        }
        if request
            .rating
            .is_some_and(|rating| !(1..=5).contains(&rating))
        {
            return Err(Error::new(
                ErrorKind::Validation,
                "feedback rating must be between 1 and 5",
            ));
        }
        let (body, content_type) = self.build_feedback_payload(request).await?;
        self.inner
            .send_and_verify(ProtocolRequest {
                operation: OperationClass::Feedback,
                method: reqwest::Method::POST,
                path: "/api/client/feedback".into(),
                query: Vec::new(),
                body,
                encrypt_body: true,
                require_session: true,
                require_trusted_time: true,
                require_online_key: true,
                content_type: Some(content_type),
            })
            .await
    }

    pub async fn request_enrollment_ticket(&self, audience: String) -> Result<EnrollmentTicket> {
        self.ensure_not_closed()?;
        let audience = audience.trim().to_ascii_lowercase();
        if audience.is_empty() {
            return Err(Error::new(
                ErrorKind::Validation,
                "enrollment audience is required",
            ));
        }
        self.inner
            .send_and_verify(ProtocolRequest {
                operation: OperationClass::Enrollment,
                method: reqwest::Method::POST,
                path: "/api/client/enrollment-ticket".into(),
                query: Vec::new(),
                body: serde_json::to_vec(&EnrollmentWireRequest { audience })?,
                encrypt_body: true,
                require_session: true,
                require_trusted_time: true,
                require_online_key: true,
                content_type: None,
            })
            .await
    }

    pub async fn rotate_device_key(&self) -> Result<DeviceKeyRotationResult> {
        self.ensure_not_closed()?;
        if !self.inner.clock.is_initialized() {
            self.inner.refresh_trusted_time().await?;
        }
        self.inner.refresh_online_keys(false).await?;
        let _ = self.inner.ensure_session()?;
        let pending = PendingIdentityGuard::new(DeviceIdentity::create_pending(
            &self.inner.options.app_id,
            self.inner.store.clone(),
        )?);
        let mut challenge = None;
        let mut proof_digest = None;
        for attempt in 0..2 {
            let device_auth = self
                .create_device_auth_for(pending.get(), challenge.clone())
                .await?;
            let new_key_proof = if let (Some(_), Some(digest)) = (&challenge, &proof_digest) {
                let bytes = hex::decode(digest).map_err(|_| {
                    Error::new(ErrorKind::Protocol, "rotation proof digest is invalid")
                })?;
                Some(crate::crypto::base64url_encode(
                    &pending.get().sign_digest(&bytes)?,
                ))
            } else {
                None
            };
            let response = self
                .inner
                .send(ProtocolRequest {
                    operation: OperationClass::Rotation,
                    method: reqwest::Method::POST,
                    path: "/api/client/device-key/rotate".into(),
                    query: Vec::new(),
                    body: serde_json::to_vec(&DeviceKeyRotationWireRequest {
                        new_device_auth: device_auth,
                        new_key_proof,
                    })?,
                    encrypt_body: true,
                    require_session: true,
                    require_trusted_time: true,
                    require_online_key: true,
                    content_type: None,
                })
                .await?;
            if response.status.as_u16() == 428 && attempt == 0 {
                let value: DeviceKeyRotationChallenge = serde_json::from_slice(&response.body)?;
                if value.challenge.is_empty()
                    || value.proof_digest.is_empty()
                    || value.expires_at <= self.inner.clock.now_unix_seconds()
                {
                    return Err(Error::new(
                        ErrorKind::Protocol,
                        "device key rotation challenge is invalid",
                    ));
                }
                challenge = Some(value.challenge);
                proof_digest = Some(value.proof_digest);
                continue;
            }
            self.inner.throw_if_error(&response)?;
            let value: DeviceKeyRotationWireResponse = serde_json::from_slice(&response.body)?;
            if !value.rotated
                || !crate::options::is_uuid(&value.registration_id)
                || value.install_id != pending.get().install_id
                || value.key_id != pending.get().key_id
            {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "device key rotation response is invalid",
                ));
            }
            let pending = pending.take();
            if let Err(error) = pending.commit_pending() {
                pending.delete_pending();
                return Err(error);
            }
            let previous = {
                let mut identity = self.inner.identity.lock().await;
                identity.replace(std::sync::Arc::new(pending))
            };
            if let Some(previous) = previous {
                previous.close();
            }
            self.inner.clear_session();
            return Ok(DeviceKeyRotationResult {
                registration_id: value.registration_id,
                install_id: value.install_id,
                key_id: value.key_id,
                device_id: self.device_id().await?,
            });
        }
        Err(Error::new(
            ErrorKind::Protocol,
            "device key rotation challenge retry was exhausted",
        ))
    }

    pub async fn authorize_operation(
        &self,
        request: OperationAuthorizationRequest,
    ) -> Result<OperationGrant> {
        self.ensure_not_closed()?;
        if self.is_offline_locked() {
            return Err(Error::new(
                ErrorKind::OfflineBudget,
                "offline budget exceeded",
            ));
        }
        let operation = request.operation.trim().to_string();
        let consumer_module = request.consumer_module.trim().to_string();
        if operation.is_empty()
            || request.plan.is_empty()
            || request.step_count == 0
            || request.step_count > 100000
        {
            return Err(Error::new(
                ErrorKind::Validation,
                "operation authorization request is invalid",
            ));
        }
        if consumer_module.is_empty() {
            return Err(Error::new(
                ErrorKind::Validation,
                "consumer_module is required",
            ));
        }
        let has_host_path = request.host_executable_path.is_some();
        let has_module_path = request.consumer_module_path.is_some();
        if has_host_path != has_module_path {
            return Err(Error::new(
                ErrorKind::Validation,
                "host and consumer module paths must be provided together",
            ));
        }
        let host_bound = has_host_path || self.host_policy_required();
        if host_bound && !has_host_path {
            return Err(Error::new(
                ErrorKind::Validation,
                "host-bound operation requires both paths",
            ));
        }
        let challenge = match request.consumer_challenge {
            Some(value) if value.len() == 32 => value,
            Some(_) => {
                return Err(Error::new(
                    ErrorKind::Validation,
                    "consumer challenge must contain exactly 32 bytes",
                ));
            }
            None => random_bytes(32)?,
        };
        let (manifest_sha, host_hash, module_hash) = if host_bound {
            let evidence = self.inner.host.get_required_evidence().await?;
            let (host, module) = self
                .inner
                .host
                .resolve_operation_hashes(
                    request.host_executable_path.as_deref().unwrap(),
                    request.consumer_module_path.as_deref().unwrap(),
                )
                .await?;
            (evidence.integrity_manifest_sha256, Some(host), Some(module))
        } else {
            (None, None, None)
        };
        let payload = OperationAuthorizationWireRequest {
            schema: if host_bound {
                "operation_grant_v3_host".into()
            } else {
                "operation_grant_v3_unbound".into()
            },
            operation,
            plan_sha256: sha256_hex(&request.plan),
            step_count: request.step_count,
            total_bytes: request.total_bytes,
            consumer_challenge: hex::encode(challenge),
            integrity_manifest_sha256: manifest_sha,
            host_exe_sha256: host_hash,
            consumer_module,
            consumer_module_sha256: module_hash,
        };
        self.inner
            .send_and_verify(ProtocolRequest {
                operation: OperationClass::OperationAuthorization,
                method: reqwest::Method::POST,
                path: "/api/client/operation-authorizations".into(),
                query: Vec::new(),
                body: serde_json::to_vec(&payload)?,
                encrypt_body: true,
                require_session: true,
                require_trusted_time: true,
                require_online_key: true,
                content_type: None,
            })
            .await
    }

    pub async fn consume_operation_authorization(
        &self,
        grant: OperationGrant,
    ) -> Result<OperationConsumptionReceipt> {
        self.ensure_not_closed()?;
        if self.is_offline_locked() {
            return Err(Error::new(
                ErrorKind::OfflineBudget,
                "offline budget exceeded",
            ));
        }
        if !matches!(
            grant.schema.as_str(),
            "operation_grant_v3_host" | "operation_grant_v3_unbound"
        ) || !crate::options::is_uuid(&grant.grant_id)
            || grant.operation.is_empty()
            || grant.plan_sha256.len() != 64
            || grant.consumer_module.is_empty()
            || grant.consumer_challenge.is_empty()
            || grant.step_count == 0
            || grant.issued_at <= 0
            || grant.expires_at <= grant.issued_at
        {
            return Err(Error::new(
                ErrorKind::Validation,
                "operation grant is incomplete or invalid",
            ));
        }
        let payload = OperationConsumeWireRequest {
            schema: "operation_grant_consume_v2".into(),
            grant_id: grant.grant_id,
            operation: grant.operation,
            plan_sha256: grant.plan_sha256,
            step_count: grant.step_count,
            total_bytes: grant.total_bytes,
            consumer_challenge: grant.consumer_challenge,
            issued_at: grant.issued_at,
            expires_at: grant.expires_at,
            integrity_manifest_sha256: grant.integrity_manifest_sha256,
            host_exe_sha256: grant.host_exe_sha256,
            consumer_module: grant.consumer_module,
            consumer_module_sha256: grant.consumer_module_sha256,
        };
        self.inner
            .send_and_verify(ProtocolRequest {
                operation: OperationClass::OperationConsume,
                method: reqwest::Method::POST,
                path: "/api/client/operation-authorizations/consume".into(),
                query: Vec::new(),
                body: serde_json::to_vec(&payload)?,
                encrypt_body: true,
                require_session: true,
                require_trusted_time: true,
                require_online_key: true,
                content_type: None,
            })
            .await
    }

    pub(crate) async fn create_device_auth_for(
        &self,
        identity: &DeviceIdentity,
        challenge: Option<String>,
    ) -> Result<DeviceAuthRegistration> {
        Ok(DeviceAuthRegistration {
            install_id: identity.install_id.clone(),
            key_id: identity.key_id.clone(),
            key_thumbprint: identity.key_thumbprint.clone(),
            public_key_sec1: crate::crypto::base64url_encode(&identity.public_key_sec1),
            credential_version: "device_credential_v2".into(),
            challenge,
            hardware_evidence: self.hardware_evidence()?,
        })
    }

    async fn build_feedback_payload(&self, request: FeedbackRequest) -> Result<(Vec<u8>, String)> {
        let boundary = format!(
            "----------------------------{}",
            hex::encode(random_bytes(12)?)
        );
        let mut body = Vec::new();
        let mut field = |name: &str, value: &str| {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(value.as_bytes());
            body.extend_from_slice(b"\r\n");
        };
        field("device_id", &self.device_id().await?);
        field("channel_code", &self.inner.options.channel);
        field("content", &request.content);
        if let Some(rating) = request.rating {
            field("rating", &rating.to_string());
        }
        if let Some(contact) = request.contact {
            field("contact", &contact);
        }
        let app_version = request
            .app_version
            .unwrap_or_else(|| self.inner.options.version.clone());
        field("app_version", &app_version);
        if let Some(metadata) = request.metadata {
            field("metadata", &serde_json::to_string(&metadata)?);
        }
        if request.attachment_paths.len() > 3 {
            return Err(Error::new(
                ErrorKind::Validation,
                "feedback supports at most 3 attachments",
            ));
        }
        for path in request.attachment_paths {
            let metadata = tokio::fs::metadata(&path).await?;
            if !metadata.is_file() {
                return Err(Error::new(
                    ErrorKind::Validation,
                    "feedback attachment is not a file",
                ));
            }
            if metadata.len() > 5 * 1024 * 1024 {
                return Err(Error::new(
                    ErrorKind::Validation,
                    "feedback attachment exceeds 5 MiB",
                ));
            }
            let estimated_total = (body.len() as u64)
                .checked_add(metadata.len())
                .and_then(|value| value.checked_add(1024))
                .ok_or_else(|| {
                    Error::new(ErrorKind::Validation, "feedback payload size overflow")
                })?;
            if estimated_total > 32 * 1024 * 1024 {
                return Err(Error::new(
                    ErrorKind::Validation,
                    "feedback payload exceeds 32 MiB",
                ));
            }
            let data = tokio::fs::read(&path).await?;
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("attachment");
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"attachments\"; filename=\"{name}\"\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
            body.extend_from_slice(&data);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        if body.len() > 32 * 1024 * 1024 {
            return Err(Error::new(
                ErrorKind::Validation,
                "feedback payload exceeds 32 MiB",
            ));
        }
        Ok((body, format!("multipart/form-data; boundary={boundary}")))
    }
}

struct PendingIdentityGuard {
    identity: Option<DeviceIdentity>,
}

impl PendingIdentityGuard {
    fn new(identity: DeviceIdentity) -> Self {
        Self {
            identity: Some(identity),
        }
    }

    fn get(&self) -> &DeviceIdentity {
        self.identity
            .as_ref()
            .expect("pending identity is available")
    }

    fn take(mut self) -> DeviceIdentity {
        self.identity.take().expect("pending identity is available")
    }
}

impl Drop for PendingIdentityGuard {
    fn drop(&mut self) {
        if let Some(identity) = self.identity.take() {
            identity.delete_pending();
        }
    }
}

pub(crate) fn verify_update_artifact(
    update: &UpdateInfo,
    options: &crate::options::ClientOptions,
) -> Result<()> {
    if !update.update_available
        || update.open_in_browser
        || update
            .delivery_method
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("external_link"))
    {
        return Ok(());
    }
    let required = [
        &update.release_id,
        &update.version,
        &update.download_url,
        &update.artifact_file_name,
        &update.manifest_key_id,
        &update.manifest_public_key,
        &update.root_trust_key_id,
        &update.root_trust_signature,
        &update.signature,
        &update.checksum_sha256,
    ];
    if required
        .iter()
        .any(|value| value.as_deref().unwrap_or("").is_empty())
        || update.size <= 0
        || !update
            .artifact_platform
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("windows"))
        || !update
            .artifact_arch
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(&options.arch))
    {
        return Err(Error::new(
            ErrorKind::Integrity,
            "artifact manifest is incomplete",
        ));
    }
    if update.root_trust_key_id.as_deref() != Some(options.root_trust_key_id.as_str()) {
        return Err(Error::new(
            ErrorKind::Integrity,
            "artifact root trust key mismatch",
        ));
    }
    let root_canonical = [
        "root_trust_manifest_v1".to_string(),
        format!("app_id:{}", options.app_id),
        format!("signer_key_id:{}", options.root_trust_key_id),
        format!(
            "key_id:{}",
            update.manifest_key_id.as_deref().unwrap_or_default()
        ),
        format!(
            "public_key:{}",
            update.manifest_public_key.as_deref().unwrap_or_default()
        ),
    ]
    .join("\n");
    if !crate::crypto::verify_ed25519(
        &options.root_trust_public_key,
        root_canonical.as_bytes(),
        update.root_trust_signature.as_deref().unwrap_or_default(),
    )? {
        return Err(Error::new(
            ErrorKind::Integrity,
            "artifact root trust signature is invalid",
        ));
    }
    verify_artifact_manifest(update)
}

pub(crate) fn verify_artifact_manifest(update: &UpdateInfo) -> Result<()> {
    let canonical = [
        "artifact_manifest_v1".to_string(),
        format!(
            "release_id:{}",
            update.release_id.as_deref().unwrap_or_default()
        ),
        format!(
            "release_version:{}",
            update.version.as_deref().unwrap_or_default()
        ),
        format!(
            "version_code:{}",
            update
                .version_code
                .map(|value| value.to_string())
                .unwrap_or_default()
        ),
        format!(
            "platform:{}",
            update
                .artifact_platform
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
        ),
        format!(
            "arch:{}",
            update
                .artifact_arch
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
        ),
        format!("size:{}", update.size),
        format!(
            "sha256:{}",
            update
                .checksum_sha256
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
        ),
        format!(
            "key_id:{}",
            update.manifest_key_id.as_deref().unwrap_or_default()
        ),
    ]
    .join("\n");
    if !crate::crypto::verify_ed25519(
        update.manifest_public_key.as_deref().unwrap_or_default(),
        canonical.as_bytes(),
        update.signature.as_deref().unwrap_or_default(),
    )? {
        return Err(Error::new(
            ErrorKind::Integrity,
            "artifact manifest signature is invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::ClientOptions;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use ed25519_dalek::{Signer, SigningKey};
    use hkdf::Hkdf;
    use sha2::{Digest, Sha256, Sha512};
    use std::io::Write;
    use std::time::Instant;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
    use x25519_dalek::{PublicKey, StaticSecret};

    #[tokio::test]
    async fn feedback_multipart_contains_expected_fields() {
        let directory = tempfile::tempdir().unwrap();
        let client = Client::new(
            ClientOptions::builder()
                .base_url("https://swm.example.test")
                .app_id("00000000-0000-0000-0000-000000001201")
                .release_id("00000000-0000-0000-0000-000000001202")
                .version("1.0.0")
                .root_trust_key_id("root-1201")
                .root_trust_public_key(hex::encode([0u8; 32]))
                .device_id("device-1201")
                .storage_directory(directory.path().to_path_buf())
                .build()
                .unwrap(),
        )
        .unwrap();
        let attachment = directory.path().join("screen.txt");
        let mut file = std::fs::File::create(&attachment).unwrap();
        file.write_all(b"attachment body").unwrap();
        let (body, content_type) = client
            .build_feedback_payload(FeedbackRequest {
                content: "feedback content".into(),
                rating: Some(5),
                contact: Some("user@example.com".into()),
                app_version: Some("1.2.3".into()),
                attachment_paths: vec![attachment],
                metadata: Some(serde_json::json!({"os": "windows"})),
            })
            .await
            .unwrap();
        assert!(content_type.starts_with("multipart/form-data; boundary="));
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("name=\"content\""));
        assert!(body.contains("name=\"rating\""));
        assert!(body.contains("name=\"metadata\""));
        assert!(body.contains("name=\"attachments\""));
        assert!(body.contains("attachment body"));
    }

    #[tokio::test]
    async fn feedback_end_to_end_verifies_authz_response() {
        let app_id = "00000000-0000-0000-0000-000000001301";
        let release_id = "00000000-0000-0000-0000-000000001302";
        let device_id = "device-1301";
        let key_id = "online-key-1301";
        let session = "session-1301";
        let seed = [0x66u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let x25519_private = x25519_private_from_seed(&seed);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/client/feedback"))
            .respond_with(FeedbackResponder {
                app_id: app_id.into(),
                release_id: release_id.into(),
                device_id: device_id.into(),
                key_id: key_id.into(),
                session: session.into(),
                signing_key,
                x25519_private,
                x25519_public: public_key,
            })
            .mount(&server)
            .await;
        let client = Client::new(
            ClientOptions::builder()
                .base_url(server.uri())
                .app_id(app_id)
                .release_id(release_id)
                .version("1.0.0")
                .root_trust_key_id("root-1301")
                .root_trust_public_key(hex::encode([0u8; 32]))
                .device_id(device_id)
                .allow_insecure_http(true)
                .storage_directory(tempfile::tempdir().unwrap().keep())
                .build()
                .unwrap(),
        )
        .unwrap();
        let identity = client.identity().await.unwrap();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        client
            .inner
            .clock
            .set_authoritative(now * 1000, Instant::now(), Instant::now())
            .unwrap();
        *client.inner.current_key.lock().unwrap() = Some(crate::pipeline::ProtocolKey {
            key_id: key_id.into(),
            public_key: hex::encode(public_key),
            refresh_after: now + 3600,
        });
        client.inner.install_session(session.into(), now + 600);

        let attachment = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(attachment.path(), b"feedback attachment").unwrap();
        let result = client
            .submit_feedback(FeedbackRequest {
                content: "feedback content".into(),
                rating: Some(5),
                contact: Some("user@example.com".into()),
                app_version: Some("1.0.0".into()),
                attachment_paths: vec![attachment.path().to_path_buf()],
                metadata: Some(serde_json::json!({"os": "windows"})),
            })
            .await
            .unwrap();
        assert!(result.ok);
        assert_eq!(result.id, "00000000-0000-0000-0000-000000001303");
        identity.delete_pending();
    }

    struct FeedbackResponder {
        app_id: String,
        release_id: String,
        device_id: String,
        key_id: String,
        session: String,
        signing_key: SigningKey,
        x25519_private: StaticSecret,
        x25519_public: [u8; 32],
    }

    impl Respond for FeedbackResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let timestamp = request
                .headers
                .get("X-Timestamp")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let nonce = request
                .headers
                .get("X-Nonce")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let Ok(plaintext) = decrypt_feedback_body(
                &request.body,
                &self.x25519_private,
                self.x25519_public,
                &self.key_id,
                &self.app_id,
                &self.release_id,
                &timestamp,
                &nonce,
            ) else {
                return ResponseTemplate::new(400);
            };
            let text = String::from_utf8_lossy(&plaintext);
            if !text.contains("feedback content")
                || !text.contains("name=\"attachments\"")
                || !text.contains("feedback attachment")
            {
                return ResponseTemplate::new(422);
            }
            let data = br#"{"ok":true,"id":"00000000-0000-0000-0000-000000001303"}"#;
            let issued_at = time::OffsetDateTime::now_utc().unix_timestamp();
            let expires_at = issued_at + 600;
            let canonical = [
                "authz_v3".to_string(),
                format!("app_id:{}", self.app_id),
                format!("release_id:{}", self.release_id),
                format!("device_id:{}", self.device_id),
                format!("nonce:{nonce}"),
                "decision:allow".into(),
                "reason:".into(),
                format!("data_sha256:{}", sha256_hex(data)),
                format!("session:{}", self.session),
                format!("issued_at:{issued_at}"),
                format!("expires_at:{expires_at}"),
                format!("key_id:{}", self.key_id),
            ]
            .join("\n");
            let signature = crate::crypto::base64url_encode(
                &self.signing_key.sign(canonical.as_bytes()).to_bytes(),
            );
            let authz = serde_json::json!({
                    "version": "authz_v3",
                    "decision": "allow",
                    "release_id": self.release_id,
                    "device_id": self.device_id,
                    "nonce": nonce,
                    "data_sha256": sha256_hex(data),
                    "session": self.session,
                    "issued_at": issued_at,
                    "expires_at": expires_at,
                    "key_id": self.key_id,
                    "signature": signature
            });
            let body = format!(
                r#"{{"data":{},"authz":{}}}"#,
                String::from_utf8_lossy(data),
                authz
            );
            ResponseTemplate::new(200).set_body_raw(body, "application/json")
        }
    }

    fn x25519_private_from_seed(seed: &[u8; 32]) -> StaticSecret {
        let digest = Sha512::digest(seed);
        let mut private = [0u8; 32];
        private.copy_from_slice(&digest[..32]);
        private[0] &= 248;
        private[31] &= 127;
        private[31] |= 64;
        StaticSecret::from(private)
    }

    fn decrypt_feedback_body(
        body: &[u8],
        private_key: &StaticSecret,
        public_key: [u8; 32],
        key_id: &str,
        app_id: &str,
        release_id: &str,
        timestamp: &str,
        nonce: &str,
    ) -> std::result::Result<Vec<u8>, String> {
        if body.len() < 32 + 12 + 16 {
            return Err("body is truncated".into());
        }
        let ephemeral: [u8; 32] = body[..32].try_into().map_err(|_| "bad ephemeral key")?;
        let shared = private_key.diffie_hellman(&PublicKey::from(ephemeral));
        let context = [
            crate::crypto::BODY_ENCRYPTION_LABEL,
            &format!("app_id:{app_id}"),
            &format!("release_id:{release_id}"),
            &format!("key_id:{key_id}"),
            &format!("public_key:{}", hex::encode(public_key)),
        ]
        .join("\n");
        let salt = crate::crypto::sha256(context.as_bytes());
        let info = format!(
            "{context}\nephemeral_public:{}",
            crate::crypto::base64url_encode(&body[..32])
        );
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(info.as_bytes(), &mut key)
            .map_err(|_| "hkdf failed")?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "cipher failed")?;
        let aad = crate::crypto::build_body_encryption_aad(
            "POST",
            "/api/client/feedback",
            "",
            timestamp.parse().map_err(|_| "timestamp invalid")?,
            nonce,
            app_id,
            release_id,
            "1.0.0",
            None,
            key_id,
        );
        cipher
            .decrypt(
                Nonce::from_slice(&body[32..44]),
                Payload {
                    msg: &body[44..],
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| "decrypt failed".into())
    }
}
