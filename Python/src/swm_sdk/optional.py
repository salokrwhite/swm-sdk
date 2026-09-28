from __future__ import annotations

import json
import time
from typing import Any

import requests

from .crypto import base64url_encode, hmac_sha256_hex, random_bytes, random_uuid, sha256_hex
from .errors import ErrorKind, SwmError
from .models import DebugCredentials, DebugRequestTicket
from .pipeline import (
    ProtocolResponse,
    backoff,
    is_transient_status,
    policy_for,
    retry_after,
)


class OptionalMixin:
    def resolve_firmware_identity(self, metadata: dict[str, str]) -> dict[str, Any]:
        allowed = {
            "ota_target_version",
            "version_name",
            "post_build",
            "oplus_rom_version",
            "android_version",
            "post_sdk_level",
        }
        normalized = {
            key: value
            for key, value in metadata.items()
            if key in allowed and value and len(value) <= 512
        }
        if not normalized:
            raise SwmError(ErrorKind.VALIDATION, "firmware metadata must contain a supported field")
        response = self._send_web_operation(  # type: ignore[attr-defined]
            "POST",
            "/api/v1/device-models/resolve",
            json.dumps(normalized, separators=(",", ":")).encode("utf-8"),
            credentials=None,
            watch_token=None,
        )
        self._throw_if_error(response)  # type: ignore[attr-defined]
        return _decode_json_object(response.body, "firmware identity response")

    def create_debug_request(self, note: str) -> DebugRequestTicket:
        if len(note) < 2 or len(note) > 200:
            raise SwmError(ErrorKind.VALIDATION, "debug note must contain 2 to 200 characters")
        session_id = base64url_encode(random_bytes(32))
        enrollment = self.request_enrollment_ticket("debug")  # type: ignore[attr-defined]
        enroll_body = json.dumps(
            {
                "ticket": enrollment.ticket,
                "app_id": self.options.app_id,  # type: ignore[attr-defined]
                "release_id": self.options.release_id,  # type: ignore[attr-defined]
                "session_id": session_id,
                "pcid": self.device_id(),  # type: ignore[attr-defined]
                "app_version": self.options.version,  # type: ignore[attr-defined]
            },
            separators=(",", ":"),
        ).encode("utf-8")
        enroll_response = self._send_web_public("/api/v1/client/debug-enroll", enroll_body)  # type: ignore[attr-defined]
        self._throw_if_error(enroll_response)  # type: ignore[attr-defined]
        enrolled = _decode_json_object(enroll_response.body, "debug enrollment response")
        now = self._clock.now_seconds()  # type: ignore[attr-defined]
        expires_at = _required_int(enrolled, "expires_at", "debug enrollment response")
        if (
            not enrolled.get("client_id")
            or not enrolled.get("client_secret")
            or expires_at <= now
            or expires_at > now + 305
        ):
            raise SwmError(ErrorKind.PROTOCOL, "debug enrollment response is invalid")
        credentials = DebugCredentials(
            client_id=str(enrolled["client_id"]),
            client_secret=str(enrolled["client_secret"]),
            expires_at=expires_at,
        )
        create_response = self._send_web_operation(  # type: ignore[attr-defined]
            "POST",
            "/api/v1/client/debug-requests",
            json.dumps(
                {
                    "session_id": session_id,
                    "pcid": self.device_id(),  # type: ignore[attr-defined]
                    "app_version": self.options.version,  # type: ignore[attr-defined]
                    "note": note,
                },
                separators=(",", ":"),
            ).encode("utf-8"),
            credentials=credentials,
            watch_token=None,
        )
        self._throw_if_error(create_response)  # type: ignore[attr-defined]
        created = _decode_json_object(create_response.body, "debug create response")
        created_expires_at = _required_int(created, "expires_at", "debug create response")
        if (
            not _is_uuid(str(created.get("request_id", "")))
            or not created.get("watch_token")
            or created_expires_at <= now
            or created_expires_at > now + 305
        ):
            raise SwmError(ErrorKind.PROTOCOL, "debug create response is invalid")
        return DebugRequestTicket(
            request_id=str(created["request_id"]),
            watch_token=str(created["watch_token"]),
            expires_at=created_expires_at,
            credentials=credentials,
            session_id=session_id,
        )

    def cancel_debug_request(self, ticket: DebugRequestTicket) -> None:
        if not ticket.request_id or not ticket.watch_token or not ticket.credentials.client_id:
            raise SwmError(ErrorKind.VALIDATION, "debug ticket is incomplete")
        response = self._send_web_operation(  # type: ignore[attr-defined]
            "POST",
            f"/api/v1/client/debug-requests/{ticket.request_id}/cancel",
            b"",
            credentials=ticket.credentials,
            watch_token=ticket.watch_token,
        )
        self._throw_if_error(response)  # type: ignore[attr-defined]

    def _open_debug_stream(self, ticket: DebugRequestTicket) -> tuple[Any, str]:
        if not self._clock.is_initialized():  # type: ignore[attr-defined]
            self._refresh_trusted_time()  # type: ignore[attr-defined]
        session = self._ensure_session()  # type: ignore[attr-defined]
        path = f"/api/v1/client/debug-requests/{ticket.request_id}/events"
        url = self._make_web_url(path)  # type: ignore[attr-defined]
        timestamp = str(self._clock.now_seconds())  # type: ignore[attr-defined]
        nonce = random_uuid()
        signature = _debug_hmac(
            ticket.credentials.client_secret,
            "GET",
            path,
            b"",
            timestamp,
            nonce,
            ticket.credentials.client_id,
        )
        headers = {
            "Accept": "text/event-stream",
            "X-Client-ID": ticket.credentials.client_id,
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Signature-Version": "1",
            "X-Signature": signature,
            "X-Debug-Watch-Token": ticket.watch_token,
            "X-SWM-Session": session,
            "X-SWM-DPoP": self._create_dpop("GET", url, session, b""),  # type: ignore[attr-defined]
        }
        try:
            response = self._http.get(  # type: ignore[attr-defined]
                url,
                headers=headers,
                stream=True,
                allow_redirects=False,
            )
        except requests.Timeout as error:
            raise SwmError(ErrorKind.TIMEOUT, "debug stream request timed out", cause=error) from error
        except requests.RequestException as error:
            raise SwmError(ErrorKind.NETWORK, "debug stream request failed", cause=error) from error
        return response, nonce

    def _send_web_operation(
        self,
        method: str,
        path: str,
        body: bytes,
        credentials: DebugCredentials | None,
        watch_token: str | None,
    ) -> ProtocolResponse:
        self._ensure_not_closed()  # type: ignore[attr-defined]
        if not self._clock.is_initialized():  # type: ignore[attr-defined]
            self._refresh_trusted_time()  # type: ignore[attr-defined]
        session = self._ensure_session()  # type: ignore[attr-defined]
        url = self._make_web_url(path)  # type: ignore[attr-defined]
        policy = policy_for("debug")
        started = time.monotonic()
        last_error: SwmError | None = None
        for attempt in range(policy.retries + 1):
            if policy.deadline > 0 and time.monotonic() - started + policy.timeout > policy.deadline:
                break
            try:
                response = self._send_web_attempt(
                    method,
                    path,
                    url,
                    body,
                    session,
                    credentials,
                    watch_token,
                    policy.timeout,
                )
                if 200 <= response.status_code < 400:
                    return response
                if is_transient_status(response.status_code) and attempt < policy.retries:
                    delay = retry_after(response.headers)
                    if delay is None:
                        delay = backoff(policy, attempt)
                    if policy.deadline > 0 and (
                        time.monotonic() - started + delay + policy.timeout > policy.deadline
                    ):
                        return response
                    time.sleep(delay)
                    continue
                return response
            except SwmError as error:
                last_error = error
                if error.kind not in {ErrorKind.NETWORK, ErrorKind.TIMEOUT} or attempt >= policy.retries:
                    break
                delay = backoff(policy, attempt)
                if policy.deadline > 0 and (
                    time.monotonic() - started + delay + policy.timeout > policy.deadline
                ):
                    break
                time.sleep(delay)
        raise last_error or SwmError(ErrorKind.TIMEOUT, "debug request deadline exceeded")

    def _send_web_attempt(
        self,
        method: str,
        path: str,
        url: str,
        body: bytes,
        session: str,
        credentials: DebugCredentials | None,
        watch_token: str | None,
        timeout: float,
    ) -> ProtocolResponse:
        timestamp = str(self._clock.now_seconds())  # type: ignore[attr-defined]
        nonce = random_uuid()
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "X-SWM-Session": session,
            "X-SWM-DPoP": self._create_dpop(method, url, session, body),  # type: ignore[attr-defined]
        }
        if credentials is not None:
            headers.update(
                {
                    "X-Client-ID": credentials.client_id,
                    "X-Timestamp": timestamp,
                    "X-Nonce": nonce,
                    "X-Signature-Version": "1",
                    "X-Signature": _debug_hmac(
                        credentials.client_secret,
                        method,
                        path,
                        body,
                        timestamp,
                        nonce,
                        credentials.client_id,
                    ),
                }
            )
        if watch_token:
            headers["X-Debug-Watch-Token"] = watch_token
        try:
            response = self._http.request(  # type: ignore[attr-defined]
                method,
                url,
                headers=headers,
                data=body,
                timeout=timeout,
                allow_redirects=False,
            )
        except requests.Timeout as error:
            raise SwmError(ErrorKind.TIMEOUT, "debug request timed out", cause=error) from error
        except requests.RequestException as error:
            raise SwmError(ErrorKind.NETWORK, "debug request failed", cause=error) from error
        try:
            content = _read_response_content(response, 4 * 1024 * 1024, "debug response")
        except requests.RequestException as error:
            raise SwmError(ErrorKind.NETWORK, "debug response read failed", cause=error) from error
        return ProtocolResponse(response.status_code, content, nonce, response.headers)

    def _send_web_public(self, path: str, body: bytes) -> ProtocolResponse:
        self._ensure_not_closed()  # type: ignore[attr-defined]
        url = self._make_web_url(path)  # type: ignore[attr-defined]
        policy = policy_for("debug")
        started = time.monotonic()
        last_error: SwmError | None = None
        for attempt in range(policy.retries + 1):
            if policy.deadline > 0 and time.monotonic() - started + policy.timeout > policy.deadline:
                break
            try:
                response = self._send_web_public_attempt(url, body, policy.timeout)
                if 200 <= response.status_code < 400:
                    return response
                if is_transient_status(response.status_code) and attempt < policy.retries:
                    delay = retry_after(response.headers)
                    if delay is None:
                        delay = backoff(policy, attempt)
                    if policy.deadline > 0 and (
                        time.monotonic() - started + delay + policy.timeout > policy.deadline
                    ):
                        return response
                    time.sleep(delay)
                    continue
                return response
            except SwmError as error:
                last_error = error
                if error.kind not in {ErrorKind.NETWORK, ErrorKind.TIMEOUT} or attempt >= policy.retries:
                    break
                delay = backoff(policy, attempt)
                if policy.deadline > 0 and (
                    time.monotonic() - started + delay + policy.timeout > policy.deadline
                ):
                    break
                time.sleep(delay)
        raise last_error or SwmError(ErrorKind.TIMEOUT, "public debug request deadline exceeded")

    def _send_web_public_attempt(self, url: str, body: bytes, timeout: float) -> ProtocolResponse:
        try:
            response = self._http.post(  # type: ignore[attr-defined]
                url,
                headers={"Content-Type": "application/json; charset=utf-8"},
                data=body,
                timeout=timeout,
                allow_redirects=False,
            )
        except requests.Timeout as error:
            raise SwmError(ErrorKind.TIMEOUT, "public debug request timed out", cause=error) from error
        except requests.RequestException as error:
            raise SwmError(ErrorKind.NETWORK, "public debug request failed", cause=error) from error
        try:
            content = _read_response_content(
                response,
                4 * 1024 * 1024,
                "public debug response",
            )
        except requests.RequestException as error:
            raise SwmError(
                ErrorKind.NETWORK,
                "public debug response read failed",
                cause=error,
            ) from error
        return ProtocolResponse(response.status_code, content, random_uuid(), response.headers)


def _debug_hmac(
    secret: str,
    method: str,
    path: str,
    body: bytes,
    timestamp: str,
    nonce: str,
    client_id: str,
) -> str:
    return hmac_sha256_hex(
        secret,
        "\n".join([method, path, "", sha256_hex(body), timestamp, nonce, client_id]),
    )


def _is_uuid(value: str) -> bool:
    import re

    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            value,
        )
    )


def _decode_json_object(raw: bytes, context: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except Exception as error:
        raise SwmError(ErrorKind.PROTOCOL, f"{context} is not valid JSON", cause=error) from error
    if not isinstance(value, dict):
        raise SwmError(ErrorKind.PROTOCOL, f"{context} must be a JSON object")
    return value


def _required_int(value: dict[str, Any], field: str, context: str) -> int:
    raw = value.get(field)
    if raw is None:
        raise SwmError(ErrorKind.PROTOCOL, f"{context} field {field} is invalid")
    try:
        return int(raw)
    except (TypeError, ValueError, OverflowError) as error:
        raise SwmError(ErrorKind.PROTOCOL, f"{context} field {field} is invalid", cause=error) from error


def _read_response_content(
    response: requests.Response,
    maximum: int,
    context: str,
) -> bytes:
    if response.raw is None or response._content_consumed:
        content = response.content
        if len(content) > maximum:
            raise SwmError(ErrorKind.PROTOCOL, f"{context} exceeds the accepted limit")
        return content
    body = bytearray()
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        body.extend(chunk)
        if len(body) > maximum:
            raise SwmError(ErrorKind.PROTOCOL, f"{context} exceeds the accepted limit")
    return bytes(body)
