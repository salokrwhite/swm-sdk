use crate::client::Client;
use crate::crypto::{base64url_encode, hmac_sha256_hex, random_bytes, random_uuid, sha256_hex};
use crate::error::{Error, ErrorKind, Result};
use crate::models::{DebugCredentials, DebugDecisionEvent, DebugRequestTicket, EnrollmentTicket};
use crate::pipeline::{OperationClass, ProtocolResponse};
use futures_util::Stream;
use serde::Serialize;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

/// Stream of verified debug decisions.
pub struct DebugStream {
    pub(crate) receiver: mpsc::Receiver<Result<DebugDecisionEvent>>,
    pub(crate) abort: AbortHandle,
}

impl Stream for DebugStream {
    type Item = Result<DebugDecisionEvent>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(context)
    }
}

impl Drop for DebugStream {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

#[derive(Serialize)]
struct DebugEnrollRequest {
    ticket: String,
    app_id: String,
    release_id: String,
    session_id: String,
    pcid: String,
    app_version: String,
}

#[derive(serde::Deserialize)]
struct DebugEnrollResponse {
    client_id: String,
    client_secret: String,
    expires_at: i64,
}

#[derive(Serialize)]
struct DebugCreateRequest {
    session_id: String,
    pcid: String,
    app_version: String,
    note: String,
}

#[derive(serde::Deserialize)]
struct DebugCreateResponse {
    request_id: String,
    watch_token: String,
    expires_at: i64,
}

impl Client {
    pub async fn resolve_firmware_identity(
        &self,
        metadata: std::collections::HashMap<String, String>,
    ) -> Result<serde_json::Value> {
        let allowed = [
            "ota_target_version",
            "version_name",
            "post_build",
            "oplus_rom_version",
            "android_version",
            "post_sdk_level",
        ];
        let normalized: std::collections::HashMap<_, _> = metadata
            .into_iter()
            .filter(|(key, value)| {
                allowed.contains(&key.as_str()) && !value.is_empty() && value.len() <= 512
            })
            .collect();
        if normalized.is_empty() {
            return Err(Error::new(
                ErrorKind::Validation,
                "firmware metadata must contain a supported field",
            ));
        }
        let response = self
            .inner
            .send_web_operation(
                reqwest::Method::POST,
                "/api/v1/device-models/resolve",
                serde_json::to_vec(&normalized)?,
                OperationClass::Firmware,
                None,
                None,
            )
            .await?;
        self.inner.throw_if_error(&response)?;
        Ok(serde_json::from_slice(&response.body)?)
    }

    pub async fn create_debug_request(&self, note: String) -> Result<DebugRequestTicket> {
        if note.chars().count() < 2 || note.chars().count() > 200 {
            return Err(Error::new(
                ErrorKind::Validation,
                "debug note must contain 2 to 200 characters",
            ));
        }
        let session_id = base64url_encode(&random_bytes(32)?);
        let enrollment: EnrollmentTicket = self.request_enrollment_ticket("debug".into()).await?;
        let enroll_body = serde_json::to_vec(&DebugEnrollRequest {
            ticket: enrollment.ticket,
            app_id: self.inner.options.app_id.clone(),
            release_id: self.inner.options.release_id.clone(),
            session_id: session_id.clone(),
            pcid: self.device_id().await?,
            app_version: self.inner.options.version.clone(),
        })?;
        let enroll_response = self
            .inner
            .send_web_public("/api/v1/client/debug-enroll", enroll_body)
            .await?;
        self.inner.throw_if_error(&enroll_response)?;
        let enrolled: DebugEnrollResponse = serde_json::from_slice(&enroll_response.body)?;
        let now = self.inner.clock.now_unix_seconds();
        if enrolled.client_id.is_empty()
            || enrolled.client_secret.is_empty()
            || enrolled.expires_at <= now
            || enrolled.expires_at > now + 305
        {
            return Err(Error::new(
                ErrorKind::Protocol,
                "debug enrollment response is invalid",
            ));
        }
        let credentials = DebugCredentials {
            client_id: enrolled.client_id,
            client_secret: enrolled.client_secret,
        };
        let create_body = serde_json::to_vec(&DebugCreateRequest {
            session_id: session_id.clone(),
            pcid: self.device_id().await?,
            app_version: self.inner.options.version.clone(),
            note,
        })?;
        let create_response = self
            .inner
            .send_web_operation(
                reqwest::Method::POST,
                "/api/v1/client/debug-requests",
                create_body,
                OperationClass::Debug,
                Some(credentials.clone()),
                None,
            )
            .await?;
        self.inner.throw_if_error(&create_response)?;
        let created: DebugCreateResponse = serde_json::from_slice(&create_response.body)?;
        if !crate::options::is_uuid(&created.request_id)
            || created.watch_token.is_empty()
            || created.expires_at <= now
            || created.expires_at > now + 305
        {
            return Err(Error::new(
                ErrorKind::Protocol,
                "debug create response is invalid",
            ));
        }
        Ok(DebugRequestTicket {
            request_id: created.request_id,
            watch_token: created.watch_token,
            expires_at: created.expires_at,
            credentials,
            session_id,
        })
    }

    pub async fn cancel_debug_request(&self, ticket: DebugRequestTicket) -> Result<()> {
        if ticket.request_id.is_empty()
            || ticket.watch_token.is_empty()
            || ticket.credentials.client_id.is_empty()
        {
            return Err(Error::new(
                ErrorKind::Validation,
                "debug ticket is incomplete",
            ));
        }
        let response = self
            .inner
            .send_web_operation(
                reqwest::Method::POST,
                &format!("/api/v1/client/debug-requests/{}/cancel", ticket.request_id),
                Vec::new(),
                OperationClass::Debug,
                Some(ticket.credentials),
                Some(ticket.watch_token),
            )
            .await?;
        self.inner.throw_if_error(&response)
    }

    pub(crate) async fn open_debug_stream(
        &self,
        ticket: &DebugRequestTicket,
    ) -> Result<(reqwest::Response, String)> {
        if !self.inner.clock.is_initialized() {
            self.inner.refresh_trusted_time().await?;
        }
        let session = self.inner.ensure_session()?;
        let path = format!("/api/v1/client/debug-requests/{}/events", ticket.request_id);
        let mut url = self.inner.web_url.clone();
        url.set_path(&path);
        let timestamp = self.inner.clock.now_unix_seconds().to_string();
        let nonce = random_uuid();
        let signature = create_debug_hmac(
            &ticket.credentials.client_secret,
            "GET",
            url.path(),
            &[],
            &timestamp,
            &nonce,
            &ticket.credentials.client_id,
        );
        let proof = self.inner.create_dpop("GET", url.as_str(), &session, &[])?;
        let response = self
            .inner
            .http
            .get(url)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .header("X-Client-ID", &ticket.credentials.client_id)
            .header("X-Timestamp", timestamp)
            .header("X-Nonce", &nonce)
            .header("X-Signature-Version", "1")
            .header("X-Signature", signature)
            .header("X-Debug-Watch-Token", &ticket.watch_token)
            .header("X-SWM-Session", session)
            .header("X-SWM-DPoP", proof)
            .send()
            .await?;
        Ok((response, nonce))
    }
}

impl crate::client::ClientInner {
    pub(crate) async fn send_web_operation(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Vec<u8>,
        _operation: OperationClass,
        credentials: Option<DebugCredentials>,
        watch_token: Option<String>,
    ) -> Result<ProtocolResponse> {
        if !self.clock.is_initialized() {
            self.refresh_trusted_time().await?;
        }
        let session = self.ensure_session()?;
        let mut url = self.web_url.clone();
        url.set_path(path);
        let timestamp = self.clock.now_unix_seconds().to_string();
        let nonce = random_uuid();
        let mut request = self
            .http
            .request(method.clone(), url.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .header("X-SWM-Session", &session)
            .header(
                "X-SWM-DPoP",
                self.create_dpop(method.as_str(), url.as_str(), &session, &body)?,
            );
        if let Some(credentials) = credentials {
            request = request
                .header("X-Client-ID", &credentials.client_id)
                .header("X-Timestamp", &timestamp)
                .header("X-Nonce", &nonce)
                .header("X-Signature-Version", "1")
                .header(
                    "X-Signature",
                    create_debug_hmac(
                        &credentials.client_secret,
                        method.as_str(),
                        url.path(),
                        &body,
                        &timestamp,
                        &nonce,
                        &credentials.client_id,
                    ),
                );
        }
        if let Some(watch_token) = watch_token {
            request = request.header("X-Debug-Watch-Token", watch_token);
        }
        let response = request.body(body).send().await?;
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

    pub(crate) async fn send_web_public(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<ProtocolResponse> {
        let mut url = self.web_url.clone();
        url.set_path(path);
        let response = self
            .http
            .post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .body(body)
            .send()
            .await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await?.to_vec();
        Ok(ProtocolResponse {
            status,
            body,
            nonce: random_uuid(),
            headers,
        })
    }
}

fn create_debug_hmac(
    secret: &str,
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: &str,
    nonce: &str,
    client_id: &str,
) -> String {
    hmac_sha256_hex(
        secret,
        &[
            method.to_string(),
            path.to_string(),
            String::new(),
            sha256_hex(body),
            timestamp.to_string(),
            nonce.to_string(),
            client_id.to_string(),
        ]
        .join("\n"),
    )
}
