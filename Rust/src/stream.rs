use crate::client::Client;
use crate::error::{Error, ErrorKind, Result};
use crate::models::{DebugDecisionEvent, DebugRequestTicket, UpdateEvent, UpdateStreamOptions};
use crate::optional::DebugStream;
use eventsource_stream::Eventsource;
use futures_util::{Stream, StreamExt};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

/// Stream of verified update events.
pub struct UpdateStream {
    pub(crate) receiver: mpsc::Receiver<Result<UpdateEvent>>,
    pub(crate) abort: AbortHandle,
}

impl Stream for UpdateStream {
    type Item = Result<UpdateEvent>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(context)
    }
}

impl Drop for UpdateStream {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

impl Client {
    pub fn watch_updates(&self, options: UpdateStreamOptions) -> UpdateStream {
        let (sender, receiver) = mpsc::channel(32);
        let client = self.clone();
        let task = tokio::spawn(async move {
            let mut attempt = 0usize;
            loop {
                match client.read_update_stream_once(&options, &sender).await {
                    Ok(()) => return,
                    Err(error) if !options.reconnect || !should_reconnect(&error) => {
                        let _ = sender.send(Err(error)).await;
                        return;
                    }
                    Err(_) => {
                        let delay = reconnect_delay(&options, attempt);
                        attempt += 1;
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        });
        UpdateStream {
            receiver,
            abort: task.abort_handle(),
        }
    }

    pub fn watch_debug_request(&self, ticket: DebugRequestTicket) -> DebugStream {
        let (sender, receiver) = mpsc::channel(16);
        let client = self.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = client.read_debug_stream_once(ticket, &sender).await {
                let _ = sender.send(Err(error)).await;
            }
        });
        DebugStream {
            receiver,
            abort: task.abort_handle(),
        }
    }

    async fn read_update_stream_once(
        &self,
        options: &UpdateStreamOptions,
        sender: &mpsc::Sender<Result<UpdateEvent>>,
    ) -> Result<()> {
        let (response, request_nonce) = self.open_update_stream(options).await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::new(
                ErrorKind::Api,
                format!("update stream failed: {status} {body}"),
            ));
        }
        let mut stream = response.bytes_stream().eventsource();
        let mut authz_verified = false;
        while let Some(event) = stream.next().await {
            let event =
                event.map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
            if event.event.eq_ignore_ascii_case("connected") {
                continue;
            }
            if event.event.eq_ignore_ascii_case("authz_expired")
                || event.event.eq_ignore_ascii_case("authz-expired")
            {
                self.clear_session();
                return Err(Error::new(
                    ErrorKind::Session,
                    "update stream authorization expired",
                ));
            }
            let data = event.data.as_bytes();
            if event.event.eq_ignore_ascii_case("authz") {
                self.inner
                    .verify_authz(&crate::pipeline::ProtocolResponse {
                        status: reqwest::StatusCode::OK,
                        body: data.to_vec(),
                        nonce: request_nonce.clone(),
                        headers: reqwest::header::HeaderMap::new(),
                    })
                    .await?;
                authz_verified = true;
                continue;
            }
            if !authz_verified {
                continue;
            }
            let verified = self
                .inner
                .verify_authz(&crate::pipeline::ProtocolResponse {
                    status: reqwest::StatusCode::OK,
                    body: data.to_vec(),
                    nonce: request_nonce.clone(),
                    headers: reqwest::header::HeaderMap::new(),
                })
                .await?;
            let mut update: UpdateEvent = serde_json::from_slice(&verified)?;
            if update.id.is_empty() {
                update.id = event.id;
            }
            if update.event_type.is_empty() {
                update.event_type = event.event;
            }
            if sender.send(Ok(update)).await.is_err() {
                return Ok(());
            }
        }
        Err(Error::new(
            ErrorKind::Network,
            "update stream closed by server",
        ))
    }

    async fn read_debug_stream_once(
        &self,
        ticket: DebugRequestTicket,
        sender: &mpsc::Sender<Result<DebugDecisionEvent>>,
    ) -> Result<()> {
        let (response, request_nonce) = self.open_debug_stream(&ticket).await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::new(
                ErrorKind::Api,
                format!("debug stream failed: {status} {body}"),
            ));
        }
        let expected_hash = crate::crypto::sha256_hex(ticket.session_id.as_bytes());
        let mut stream = response.bytes_stream().eventsource();
        while let Some(event) = stream.next().await {
            let event =
                event.map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
            if event.event != "debug-request-state" && event.event != "debug_request_state" {
                continue;
            }
            let verified = self
                .inner
                .verify_authz(&crate::pipeline::ProtocolResponse {
                    status: reqwest::StatusCode::OK,
                    body: event.data.as_bytes().to_vec(),
                    nonce: request_nonce.clone(),
                    headers: reqwest::header::HeaderMap::new(),
                })
                .await?;
            let value: serde_json::Value = serde_json::from_slice(&verified)?;
            if value.get("version").and_then(|value| value.as_str()) != Some("debug_decision_v1")
                || value.get("request_id").and_then(|value| value.as_str())
                    != Some(&ticket.request_id)
                || !value
                    .get("session_id_hash")
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case(&expected_hash))
            {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "debug decision payload is invalid",
                ));
            }
            let state = value
                .get("status")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string();
            let decision = DebugDecisionEvent {
                state: state.clone(),
                reason: value
                    .get("reason")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
                authorization_expires_at: if state == "approved" {
                    value
                        .get("expires_at")
                        .and_then(|value| value.as_i64())
                        .unwrap_or(0)
                } else {
                    0
                },
            };
            if sender.send(Ok(decision)).await.is_err() {
                return Ok(());
            }
            if matches!(state.as_str(), "approved" | "rejected" | "cancelled") {
                return Ok(());
            }
        }
        Ok(())
    }

    async fn open_update_stream(
        &self,
        options: &UpdateStreamOptions,
    ) -> Result<(reqwest::Response, String)> {
        if !self.inner.clock.is_initialized() {
            self.inner.refresh_trusted_time().await?;
        }
        let session = self.inner.ensure_session()?;
        let device_id = self.device_id().await?;
        let mut url = self.inner.base_url.clone();
        url.set_path("/api/client/updates/stream");
        url.query_pairs_mut()
            .append_pair("device_id", &device_id)
            .append_pair("channel_code", &self.inner.options.channel)
            .append_pair("platform", &self.inner.options.platform)
            .append_pair("arch", &self.inner.options.arch)
            .append_pair(
                "current_version",
                options
                    .current_version
                    .as_deref()
                    .unwrap_or(&self.inner.options.version),
            );
        if let Some(code) = options.version_code.or(self.inner.options.version_code) {
            url.query_pairs_mut()
                .append_pair("version_code", &code.to_string());
        }
        let nonce = crate::crypto::random_uuid();
        let timestamp = self.inner.clock.now_unix_seconds().to_string();
        let proof = self.inner.create_dpop("GET", url.as_str(), &session, &[])?;
        let response = self
            .inner
            .http
            .get(url)
            .header("X-App-Id", &self.inner.options.app_id)
            .header("X-Timestamp", timestamp)
            .header("X-Nonce", &nonce)
            .header("X-Authz-Capability", "v3")
            .header("X-Client-Release-Id", &self.inner.options.release_id)
            .header("X-Client-Version", &self.inner.options.version)
            .header(
                "X-Client-Version-Code",
                self.inner
                    .options
                    .version_code
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            )
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .header("X-SWM-Session", session)
            .header("X-SWM-DPoP", proof)
            .send()
            .await?;
        Ok((response, nonce))
    }
}

fn should_reconnect(error: &Error) -> bool {
    !matches!(
        error.kind,
        ErrorKind::DeviceBlocked
            | ErrorKind::UnsupportedVersion
            | ErrorKind::UpdateRegionBlocked
            | ErrorKind::Unauthorized
            | ErrorKind::Integrity
    )
}

fn reconnect_delay(options: &UpdateStreamOptions, attempt: usize) -> std::time::Duration {
    let base = if attempt == 0 {
        options.reconnect_backoff
    } else {
        match attempt {
            1 => std::time::Duration::from_millis(3000),
            2 => std::time::Duration::from_secs(6),
            _ => std::time::Duration::from_secs(20),
        }
    };
    base.min(options.reconnect_max_backoff)
}
