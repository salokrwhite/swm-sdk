from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests

from .errors import ErrorKind, SwmError
from .models import UpdateInfo
from .operations import verify_update_artifact
from .options import ProgressCallback


class DownloadMixin:
    def download_update(
        self,
        update: UpdateInfo,
        destination: str | Path,
        progress: ProgressCallback | None = None,
    ) -> None:
        self._ensure_not_closed()  # type: ignore[attr-defined]
        if not update.update_available or update.open_in_browser:
            raise SwmError(ErrorKind.VALIDATION, "update does not contain a downloadable package")
        verify_update_artifact(update, self.options)  # type: ignore[attr-defined]
        url = validate_download_url(
            update.download_url or "",
            self.options.base_url,  # type: ignore[attr-defined]
        )
        full_destination = Path(destination).resolve()
        full_destination.parent.mkdir(parents=True, exist_ok=True)
        partial = Path(str(full_destination) + ".part")
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                self._download_range(url, partial, update.size, progress)
                last_error = None
                break
            except Exception as error:
                last_error = error
                if attempt < 2:
                    import time

                    time.sleep(2 << attempt)
        if last_error is not None:
            raise last_error
        digest = hashlib.sha256()
        with partial.open("rb") as stream:
            for chunk in iter(lambda: stream.read(128 * 1024), b""):
                digest.update(chunk)
        actual = digest.hexdigest()
        if not update.checksum_sha256 or actual.lower() != update.checksum_sha256.lower():
            partial.unlink(missing_ok=True)
            raise SwmError(ErrorKind.INTEGRITY, "downloaded artifact checksum mismatch")
        os.replace(partial, full_destination)

    def _download_range(
        self,
        url: str,
        partial: Path,
        expected_size: int,
        progress: ProgressCallback | None,
    ) -> None:
        existing = partial.stat().st_size if partial.exists() else 0
        if expected_size > 0 and existing > expected_size:
            partial.unlink(missing_ok=True)
            existing = 0
        response = self._signed_download_request(url, existing)  # type: ignore[attr-defined]
        if 300 <= response.status_code < 400:
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise SwmError(ErrorKind.PROTOCOL, "download redirect is missing a location")
            storage_url = urljoin(url, location)
            storage_scheme = urlsplit(storage_url).scheme.lower()
            if storage_scheme != "https" and not self.options.allow_insecure_http:  # type: ignore[attr-defined]
                raise SwmError(ErrorKind.NETWORK, "storage redirect must use HTTPS")
            response = self._storage_request(storage_url, existing)  # type: ignore[attr-defined]
        try:
            if response.status_code >= 400:
                raise SwmError(
                    ErrorKind.NETWORK,
                    f"download failed with HTTP {response.status_code}",
                    status_code=response.status_code,
                    response_body=response.text[:1024],
                )
            append = existing > 0 and response.status_code == 206
            if not append:
                existing = 0
            expected_total = 0
            content_range = response.headers.get("Content-Range")
            if content_range and "/" in content_range:
                try:
                    expected_total = int(content_range.rsplit("/", 1)[1])
                except ValueError:
                    expected_total = 0
            elif response.headers.get("Content-Length"):
                expected_total = existing + int(response.headers["Content-Length"])
            mode = "ab" if append else "wb"
            written = existing
            with partial.open(mode) as target:
                if progress:
                    progress(written, expected_total)
                try:
                    for chunk in response.iter_content(chunk_size=128 * 1024):
                        if not chunk:
                            continue
                        target.write(chunk)
                        written += len(chunk)
                        if progress:
                            progress(written, expected_total)
                except requests.RequestException as error:
                    raise SwmError(
                        ErrorKind.NETWORK,
                        "download stream interrupted",
                        cause=error,
                    ) from error
            if expected_total and written != expected_total:
                raise SwmError(ErrorKind.PROTOCOL, "download length mismatch")
        finally:
            response.close()

    def _signed_download_request(self, url: str, range_start: int) -> requests.Response:
        if not self._clock.is_initialized():  # type: ignore[attr-defined]
            self._refresh_trusted_time()  # type: ignore[attr-defined]
        session = self._ensure_session()  # type: ignore[attr-defined]
        headers = {
            "X-SWM-Session": session,
            "X-SWM-DPoP": self._create_dpop("GET", url, session, b""),  # type: ignore[attr-defined]
        }
        if range_start:
            headers["Range"] = f"bytes={range_start}-"
        try:
            return self._http.get(  # type: ignore[attr-defined]
                url,
                headers=headers,
                stream=True,
                allow_redirects=False,
            )
        except requests.Timeout as error:
            raise SwmError(ErrorKind.TIMEOUT, "download request timed out", cause=error) from error
        except requests.RequestException as error:
            raise SwmError(ErrorKind.NETWORK, "download request failed", cause=error) from error

    def _storage_request(self, url: str, range_start: int) -> requests.Response:
        headers = {"Range": f"bytes={range_start}-"} if range_start else {}
        try:
            return self._http.get(  # type: ignore[attr-defined]
                url,
                headers=headers,
                stream=True,
                allow_redirects=False,
            )
        except requests.Timeout as error:
            raise SwmError(ErrorKind.TIMEOUT, "storage download timed out", cause=error) from error
        except requests.RequestException as error:
            raise SwmError(ErrorKind.NETWORK, "storage download failed", cause=error) from error


def validate_download_url(raw: str, base_url: str) -> str:
    parsed = urlsplit(raw)
    base = urlsplit(base_url)
    if (
        parsed.scheme.lower() != base.scheme.lower()
        or parsed.hostname != base.hostname
        or (parsed.port or (443 if parsed.scheme.lower() == "https" else 80))
        != (base.port or (443 if base.scheme.lower() == "https" else 80))
    ):
        raise SwmError(ErrorKind.INTEGRITY, "download URL is not bound to the SWM origin")
    segments = [segment for segment in parsed.path.split("/") if segment]
    if (
        len(segments) != 5
        or segments[:3] != ["api", "client", "artifacts"]
        or not re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            segments[3],
        )
        or segments[4] != "download"
        or "ticket=" not in parsed.query
    ):
        raise SwmError(ErrorKind.INTEGRITY, "download URL does not match the fixed artifact route")
    return raw
