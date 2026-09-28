use crate::client::Client;
use crate::error::{Error, ErrorKind, Result};
use crate::models::UpdateInfo;
use crate::options::ProgressCallback;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

impl Client {
    pub async fn download_update(
        &self,
        update: UpdateInfo,
        destination: PathBuf,
        progress: Option<ProgressCallback>,
    ) -> Result<()> {
        self.ensure_not_closed()?;
        if !update.update_available || update.open_in_browser {
            return Err(Error::new(
                ErrorKind::Validation,
                "update does not contain a downloadable package",
            ));
        }
        crate::operations::verify_update_artifact(&update, &self.inner.options)?;
        let url = self.validate_download_url(
            update
                .download_url
                .as_deref()
                .ok_or_else(|| Error::new(ErrorKind::Validation, "download_url is required"))?,
        )?;
        let full_destination = absolute_path(&destination)?;
        if let Some(parent) = full_destination.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let partial = PathBuf::from(format!("{}.part", full_destination.display()));
        let mut last_error = None;
        for attempt in 0..=2 {
            match self
                .download_range(&url, &partial, update.size, progress.as_ref())
                .await
            {
                Ok(()) => {
                    last_error = None;
                    break;
                }
                Err(error) => last_error = Some(error),
            }
            if attempt < 2 {
                tokio::time::sleep(std::time::Duration::from_secs(2 << attempt)).await;
            }
        }
        if let Some(error) = last_error {
            return Err(error);
        }
        let mut partial_file = tokio::fs::File::open(&partial).await?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 128 * 1024];
        loop {
            let count = partial_file.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let actual = hex::encode(hasher.finalize());
        if !update
            .checksum_sha256
            .as_deref()
            .is_some_and(|expected| expected.eq_ignore_ascii_case(&actual))
        {
            let _ = tokio::fs::remove_file(&partial).await;
            return Err(Error::new(
                ErrorKind::Integrity,
                "downloaded artifact checksum mismatch",
            ));
        }
        crate::operations::verify_artifact_manifest(&update)?;
        if tokio::fs::try_exists(&full_destination)
            .await
            .unwrap_or(false)
        {
            tokio::fs::remove_file(&full_destination).await?;
        }
        tokio::fs::rename(&partial, &full_destination).await?;
        Ok(())
    }

    async fn download_range(
        &self,
        url: &url::Url,
        partial: &Path,
        expected_size: i64,
        progress: Option<&ProgressCallback>,
    ) -> Result<()> {
        let mut existing = tokio::fs::metadata(partial)
            .await
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if expected_size > 0 && existing > expected_size as u64 {
            let _ = tokio::fs::remove_file(partial).await;
            existing = 0;
        }
        let initial = self.signed_download_request(url, existing).await?;
        let response = if initial.status().is_redirection() {
            let location = initial
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::Protocol,
                        "download redirect is missing a location",
                    )
                })?;
            let storage_url = url.join(location)?;
            if storage_url.scheme() != "https" && !self.inner.options.allow_insecure_http {
                return Err(Error::new(
                    ErrorKind::Network,
                    "storage redirect must use HTTPS",
                ));
            }
            self.storage_request(&storage_url, existing).await?
        } else {
            initial
        };
        if response.status().is_client_error() || response.status().is_server_error() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::new(
                ErrorKind::Network,
                format!("download failed: {status} {body}"),
            ));
        }
        let append = existing > 0 && response.status() == reqwest::StatusCode::PARTIAL_CONTENT;
        if !append {
            existing = 0;
        }
        let expected_total = response
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.rsplit('/').next())
            .and_then(|value| value.parse::<u64>().ok())
            .or_else(|| response.content_length().map(|value| existing + value))
            .unwrap_or(0);
        let mut options = tokio::fs::OpenOptions::new();
        options.create(true).write(true);
        if append {
            options.append(true);
        } else {
            options.truncate(true);
        }
        let mut file = options.open(partial).await?;
        if let Some(progress) = progress {
            progress(existing, expected_total);
        }
        let mut written = existing;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            file.write_all(&chunk).await?;
            written += chunk.len() as u64;
            if let Some(progress) = progress {
                progress(written, expected_total);
            }
        }
        file.flush().await?;
        if expected_total > 0 && written != expected_total {
            return Err(Error::new(ErrorKind::Protocol, "download length mismatch"));
        }
        Ok(())
    }

    async fn signed_download_request(
        &self,
        url: &url::Url,
        range_start: u64,
    ) -> Result<reqwest::Response> {
        if !self.inner.clock.is_initialized() {
            self.inner.refresh_trusted_time().await?;
        }
        let session = self.inner.ensure_session()?;
        let mut request = self.inner.http.get(url.clone());
        if range_start > 0 {
            request = request.header(reqwest::header::RANGE, format!("bytes={range_start}-"));
        }
        let proof = self.inner.create_dpop("GET", url.as_str(), &session, &[])?;
        request = request
            .header("X-SWM-Session", session)
            .header("X-SWM-DPoP", proof);
        Ok(request.send().await?)
    }

    async fn storage_request(&self, url: &url::Url, range_start: u64) -> Result<reqwest::Response> {
        let mut request = self.inner.http.get(url.clone());
        if range_start > 0 {
            request = request.header(reqwest::header::RANGE, format!("bytes={range_start}-"));
        }
        Ok(request.send().await?)
    }

    fn validate_download_url(&self, raw: &str) -> Result<url::Url> {
        let parsed = url::Url::parse(raw)?;
        if parsed.scheme() != self.inner.base_url.scheme()
            || parsed.host_str() != self.inner.base_url.host_str()
            || effective_port(&parsed) != effective_port(&self.inner.base_url)
        {
            return Err(Error::new(
                ErrorKind::Integrity,
                "download URL is not bound to the SWM origin",
            ));
        }
        let segments: Vec<_> = parsed
            .path_segments()
            .map(|segments| segments.collect())
            .unwrap_or_default();
        if segments.len() != 5
            || segments[0] != "api"
            || segments[1] != "client"
            || segments[2] != "artifacts"
            || !crate::options::is_uuid(segments[3])
            || segments[4] != "download"
            || !parsed.query().unwrap_or_default().contains("ticket=")
        {
            return Err(Error::new(
                ErrorKind::Integrity,
                "download URL does not match the fixed artifact route",
            ));
        }
        Ok(parsed)
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn effective_port(url: &url::Url) -> Option<u16> {
    url.port_or_known_default()
}
